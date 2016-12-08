/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Copyright: Eugene Wissner 2016.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:belka@caraus.de, Eugene Wissner)
 */
module tanya.async.event.iocp;

version (Windows):

import tanya.container.buffer;
import tanya.async.loop;
import tanya.async.protocol;
import tanya.async.transport;
import tanya.async.watcher;
import tanya.memory;
import tanya.memory.mmappool;
import tanya.network.socket;
import core.sys.windows.basetyps;
import core.sys.windows.mswsock;
import core.sys.windows.winbase;
import core.sys.windows.windef;
import core.sys.windows.winsock2;

class IOCPStreamTransport : StreamTransport
{
	private OverlappedConnectedSocket socket_;

	private WriteBuffer input;

	/**
	 * Creates new completion port transport.
	 * Params:
	 * 	socket = Socket.
	 */
	this(OverlappedConnectedSocket socket)
	in
	{
		assert(socket !is null);
	}
	body
	{
		socket_ = socket;
		input = MmapPool.instance.make!WriteBuffer(8192, MmapPool.instance);
	}

	~this()
	{
		MmapPool.instance.dispose(input);
	}

	@property inout(OverlappedConnectedSocket) socket() inout pure nothrow @safe @nogc
	{
		return socket_;
	}

	/**
	 * Write some data to the transport.
	 *
	 * Params:
	 * 	data = Data to send.
	 */
	void write(ubyte[] data)
	{
		immutable empty = input.length == 0;
		input ~= data;
		if (empty)
		{
			SocketState overlapped;
			try
			{
				overlapped = MmapPool.instance.make!SocketState;
				socket.beginSend(input[], overlapped);
			}
			catch (SocketException e)
			{
				MmapPool.instance.dispose(overlapped);
				MmapPool.instance.dispose(e);
			}
		}
	}
}

	class IOCPLoop : Loop
	{
	protected HANDLE completionPort;

	protected OVERLAPPED overlap;

	/**
	 * Initializes the loop.
	 */
	this()
	{
		super();

		completionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (!completionPort)
		{
			throw make!BadLoopException(defaultAllocator,
			                            "Creating completion port failed");
		}
	}

	/**
	 * Should be called if the backend configuration changes.
	 *
	 * Params:
	 * 	watcher   = Watcher.
	 * 	oldEvents = The events were already set.
	 * 	events    = The events should be set.
	 *
	 * Returns: $(D_KEYWORD true) if the operation was successful.
	 */
	override protected bool reify(ConnectionWatcher watcher,
								  EventMask oldEvents,
								  EventMask events)
	{
		SocketState overlapped;
		if (!(oldEvents & Event.accept) && (events & Event.accept))
		{
			auto socket = cast(OverlappedStreamSocket) watcher.socket;
			assert(socket !is null);

			if (CreateIoCompletionPort(cast(HANDLE) socket.handle,
									   completionPort,
									   cast(ULONG_PTR) (cast(void*) watcher),
									   0) !is completionPort)
			{
				return false;
			}

			try
			{
				overlapped = MmapPool.instance.make!SocketState;
				socket.beginAccept(overlapped);
			}
			catch (SocketException e)
			{
				MmapPool.instance.dispose(overlapped);
				defaultAllocator.dispose(e);
				return false;
			}
		}
		if (!(oldEvents & Event.read) && (events & Event.read)
			|| !(oldEvents & Event.write) && (events & Event.write))
		{
			auto io = cast(IOWatcher) watcher;
			assert(io !is null);

			auto transport = cast(IOCPStreamTransport) io.transport;
			assert(transport !is null);

			if (CreateIoCompletionPort(cast(HANDLE) transport.socket.handle,
									   completionPort,
									   cast(ULONG_PTR) (cast(void*) watcher),
									   0) !is completionPort)
			{
				return false;
			}

			// Begin to read
			if (!(oldEvents & Event.read) && (events & Event.read))
			{
				try
				{
					overlapped = MmapPool.instance.make!SocketState;
					transport.socket.beginReceive(io.output[], overlapped);
				}
				catch (SocketException e)
				{
					MmapPool.instance.dispose(overlapped);
					defaultAllocator.dispose(e);
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Does the actual polling.
	 */
	override protected void poll()
	{
		DWORD lpNumberOfBytes;
		ULONG_PTR key;
		LPOVERLAPPED overlap;
		immutable timeout = cast(immutable int) blockTime.total!"msecs";

		auto result = GetQueuedCompletionStatus(completionPort,
												&lpNumberOfBytes,
												&key,
												&overlap,
												timeout);
		if (result == FALSE && overlap == NULL)
		{
			return; // Timeout
		}

		auto overlapped = (cast(SocketState) ((cast(void*) overlap) - 8));
		assert(overlapped !is null);
		scope (failure)
		{
			MmapPool.instance.dispose(overlapped);
		}

		switch (overlapped.event)
		{
			case OverlappedSocketEvent.accept:
				auto connection = cast(ConnectionWatcher) (cast(void*) key);
				assert(connection !is null);

				auto listener = cast(OverlappedStreamSocket) connection.socket;
				assert(listener !is null);

				auto socket = listener.endAccept(overlapped);
				auto transport = MmapPool.instance.make!IOCPStreamTransport(socket);
				auto io = MmapPool.instance.make!IOWatcher(transport, connection.protocol);

				connection.incoming.insertBack(io);

				reify(io, EventMask(Event.none), EventMask(Event.read, Event.write));

				swapPendings.insertBack(connection);
				listener.beginAccept(overlapped);
				break;
			case OverlappedSocketEvent.read:
				auto io = cast(IOWatcher) (cast(void*) key);
				assert(io !is null);
				if (!io.active)
				{
					MmapPool.instance.dispose(io);
					MmapPool.instance.dispose(overlapped);
					return;
				}

				auto transport = cast(IOCPStreamTransport) io.transport;
				assert(transport !is null);

				int received;
				SocketException exception;
				try
				{
					received = transport.socket.endReceive(overlapped);
				}
				catch (SocketException e)
				{
					exception = e;
				}
				if (transport.socket.disconnected)
				{
					// We want to get one last notification to destroy the watcher
					transport.socket.beginReceive(io.output[], overlapped);
					kill(io, exception);
				}
				else if (received > 0)
				{
					immutable full = io.output.free == received;

					io.output += received;
					// Receive was interrupted because the buffer is full. We have to continue
					if (full)
					{
						transport.socket.beginReceive(io.output[], overlapped);
					}
					swapPendings.insertBack(io);
				}
				break;
			case OverlappedSocketEvent.write:
				auto io = cast(IOWatcher) (cast(void*) key);
				assert(io !is null);

				auto transport = cast(IOCPStreamTransport) io.transport;
				assert(transport !is null);

				transport.input += transport.socket.endSend(overlapped);
				if (transport.input.length)
				{
					transport.socket.beginSend(transport.input[], overlapped);
				}
				else
				{
					transport.socket.beginReceive(io.output[], overlapped);
				}
				break;
			default:
				assert(false, "Unknown event");
		}
	}
}