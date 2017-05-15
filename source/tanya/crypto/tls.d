/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Copyright: Eugene Wissner 2017.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:info@caraus.de, Eugene Wissner)
 */
module tanya.crypto.tls;

import core.sys.posix.time;
import std.algorithm.comparison;
import std.algorithm.mutation;
import std.digest.sha;
import std.digest.md;
import std.range;
import tanya.async.privkey;
import tanya.container.vector;
import tanya.crypto.aes;
import tanya.crypto.mac;
import tanya.crypto.mode;
import tanya.crypto.symmetric;
import tanya.crypto.rsa;
import tanya.crypto.x509;
import tanya.memory;
import tanya.network.inet;

enum CipherSuiteIdentifier : ushort
{
    TLS_NULL_WITH_NULL_NULL               = 0x0000,
    TLS_RSA_WITH_NULL_MD5                 = 0x0001,
    TLS_RSA_WITH_NULL_SHA                 = 0x0002,
    TLS_RSA_EXPORT_WITH_RC4_40_MD5        = 0x0003,
    TLS_RSA_WITH_RC4_128_MD5              = 0x0004,
    TLS_RSA_WITH_RC4_128_SHA              = 0x0005,
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5    = 0x0006,
    TLS_RSA_WITH_IDEA_CBC_SHA             = 0x0007,
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA     = 0x0008,
    TLS_RSA_WITH_DES_CBC_SHA              = 0x0009,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA         = 0x000A,
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA  = 0x000B,
    TLS_DH_DSS_WITH_DES_CBC_SHA           = 0x000C,
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA      = 0x000D,
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA  = 0x000E,
    TLS_DH_RSA_WITH_DES_CBC_SHA           = 0x000F,
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA      = 0x0010,
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011,
    TLS_DHE_DSS_WITH_DES_CBC_SHA          = 0x0012,
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA     = 0x0013,
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014,
    TLS_DHE_RSA_WITH_DES_CBC_SHA          = 0x0015,
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA     = 0x0016,
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5    = 0x0017,
    TLS_DH_anon_WITH_RC4_128_MD5          = 0x0018,
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x0019,
    TLS_DH_anon_WITH_DES_CBC_SHA          = 0x001A,
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA     = 0x001B,

    // 1C & 1D were used by SSLv3 to describe Fortezza suites
    // End of list of algorithms defined by RFC 2246

    // These are all defined in RFC 4346 (v1.1), not 2246 (v1.0)
    //
    TLS_KRB5_WITH_DES_CBC_SHA           = 0x001E,
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA      = 0x001F,
    TLS_KRB5_WITH_RC4_128_SHA           = 0x0020,
    TLS_KRB5_WITH_IDEA_CBC_SHA          = 0x0021,
    TLS_KRB5_WITH_DES_CBC_MD5           = 0x0022,
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5      = 0x0023,
    TLS_KRB5_WITH_RC4_128_MD5           = 0x0024,
    TLS_KRB5_WITH_IDEA_CBC_MD5          = 0x0025,
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 0x0026,
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 0x0027,
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA     = 0x0028,
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 0x0029,
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 0x002A,
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5     = 0x002B,

    // TLS_AES ciphersuites - RFC 3268
    TLS_RSA_WITH_AES_128_CBC_SHA      = 0x002F,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA   = 0x0030,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA   = 0x0031,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA  = 0x0032,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = 0x0033,
    TLS_DH_anon_WITH_AES_128_CBC_SHA  = 0x0034,
    TLS_RSA_WITH_AES_256_CBC_SHA      = 0x0035,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA   = 0x0036,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA   = 0x0037,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA  = 0x0038,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA  = 0x0039,
    TLS_DH_anon_WITH_AES_256_CBC_SHA  = 0x003A,
    TLS_RSA_WITH_AES_128_GCM_SHA256   = 0x009C,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009,

    MAX_SUPPORTED_CIPHER_SUITE        = 0xC00A
}

struct CipherSuite
{
    CipherSuiteIdentifier id;

    int hash_size;

    CipherMode bulkCipher;

    MessageAuthenticationCode mac;

    this(CipherSuiteIdentifier id,
         CipherMode bulkCipher = null,
         MessageAuthenticationCode mac = null)
    {
        this.id = id;
        this.bulkCipher = bulkCipher;
        this.hash_size = mac !is null ? mac.digestLength : 0;
        this.mac = mac;
    }
}

struct ProtectionParameters
{
    Vector!ubyte macSecret;
    Vector!ubyte key;
    Vector!ubyte iv;
    private CipherSuite cipherSuite;
    ulong sequenceNumber;

    ~this()
    {
        defaultAllocator.dispose(cipherSuite.bulkCipher);
    }

    @property CipherSuiteIdentifier suite() const pure nothrow @safe @nogc
    {
        return this.cipherSuite.id;
    }

    @property void suite(CipherSuiteIdentifier id)
    {
        switch (id) with (CipherSuiteIdentifier)
        {
            case TLS_RSA_WITH_AES_128_CBC_SHA:
                auto cipher = defaultAllocator.make!(AES!128);
                auto bulkCipher = defaultAllocator.make!(CBC)(cipher);
                auto mac = defaultAllocator.make!(HMAC!(SHA!(512u, 160u)));
                this.cipherSuite = CipherSuite(id, bulkCipher, mac);
                break;
            default:
                this.cipherSuite = CipherSuite(id);
        }
    }
}

struct HandshakeParameters
{
    ubyte[] certificateChain;
    ubyte[] key;
}

enum TLS_VERSION_MAJOR = 3;
enum TLS_VERSION_MINOR = 2;

struct TLSParameters
{
    this(void delegate(ubyte[]) sender)
    {
        this.sender = sender;
    }

    @disable this();

    ubyte[48] masterSecret;
    ubyte[32] clientRandom;
    ubyte[32] serverRandom;

    ProtectionParameters pending_send_parameters;
    ProtectionParameters active_send_parameters;
    ProtectionParameters pending_recv_parameters;
    ProtectionParameters active_recv_parameters;

    // RSA public key, if supplied
    public_key_info server_public_key;

    // Internal state
    bool gotClientHello;
    bool serverHelloDone;
    bool peerFinished;
    MD5 md5_handshake_digest;
    SHA1 sha1_handshake_digest;

    HandshakeParameters handshakeParameters;
    void delegate(ubyte[]) sender;
}

/** This lists the type of higher-level TLS protocols that are defined */
enum ContentType : ubyte
{
    changeCipherSpec = 20,
    alert = 21,
    handshake = 22,
    applicationData = 23,
}

enum AlertLevel : ubyte
{
    warning = 1,
    fatal = 2,
}

/**
 * TLS alert.
 */
final class Alert : Exception
{
    private AlertDescription description_;
    private AlertLevel level_;

    /**
     * Returns: Alert description.
     */
    @property AlertDescription description() const pure nothrow @safe @nogc
    {
        return description_;
    }

    /**
     * Returns: Alert level.
     */
    @property AlertLevel level() const pure nothrow @safe @nogc
    {
        return level_;
    }

    /**
     * Params:
     *  description = Alert description.
     *  level       = Alert level.
     *  file        = The file where the exception occurred.
     *  line        = The line number where the exception occurred.
     *  next        = The previous exception in the chain of exceptions, if any.
     */
    this(AlertDescription description,
         AlertLevel level = AlertLevel.fatal,
         string file = __FILE__,
         size_t line = __LINE__,
         Throwable next = null) @nogc @safe pure nothrow
    {
        string msg;
        description_ = description;
        level_ = level;
        final switch (description) with (AlertDescription)
        {
            case closeNotify:
                msg = "Close notify";
                break;
            case unexpectedMessage:
                msg = "Unexpected message";
                break;
            case badRecordMAC:
                msg = "Bad Record Mac";
                break;
            case decryptionFailed:
                msg = "Decryption Failed";
                break;
            case recordOverflow:
                msg = "Record Overflow";
                break;
            case decompressionFailure:
                msg = "Decompression Failure";
                break;
            case handshakeFailure:
                msg = "Handshake Failure";
                break;
            case badCertificate:
                msg = "Bad Certificate";
                break;
            case unsupportedCertificate:
                msg = "Unsupported Certificate";
                break;
            case certificateRevoked:
                msg = "Certificate Revoked";
                break;
            case certificateExpired:
                msg = "Certificate Expired";
                break;
            case certificateUnknown:
                msg = "Certificate Unknown";
                break;
            case illegalParameter:
                msg = "Illegal Parameter";
                break;
            case unknownCA:
                msg = "Unknown CA";
                break;
            case accessDenied:
                msg = "Access Denied";
                break;
            case decodeError:
                msg =  "Decode Error" ;
                break;
            case decryptError:
                msg = "Decrypt Error";
                break;
            case exportRestriction:
                msg = "Export Restriction";
                break;
            case protocolVersion:
                msg = "Protocol Version";
                break;
            case insufficientSecurity:
                msg = "Insufficient Security";
                break;
            case internalError:
                msg = "Internal Error";
                break;
            case userCanceled:
                msg = "User canceled";
                break;
            case noRenegotiation:
                msg = "No renegotiation";
                break;
        }
        super(msg, file, line, next);
    }

    /**
     * Params:
     *  description = Alert description.
     *  level       = Alert level.
     *  next        = The previous exception in the chain of exceptions.
     *  file        = The file where the exception occurred.
     *  line        = The line number where the exception occurred.
     */
    this(AlertDescription description,
         AlertLevel level,
         Throwable next,
         string file = __FILE__,
         size_t line = __LINE__) @nogc @safe pure nothrow
    {
        this(description, level, file, line, next);
    }
}

/**
 * Enumerate all of the error conditions specified by TLS.
 */
enum AlertDescription : ubyte
{
    closeNotify = 0,
    unexpectedMessage = 10,
    badRecordMAC = 20,
    decryptionFailed = 21,
    recordOverflow = 22,
    decompressionFailure = 30,
    handshakeFailure = 40,
    badCertificate = 42,
    unsupportedCertificate = 43,
    certificateRevoked = 44,
    certificateExpired = 45,
    certificateUnknown = 46,
    illegalParameter = 47,
    unknownCA = 48,
    accessDenied = 49,
    decodeError = 50,
    decryptError = 51,
    exportRestriction = 60,
    protocolVersion = 70,
    insufficientSecurity = 71,
    internalError = 80,
    userCanceled = 90,
    noRenegotiation = 100,
}

struct ProtocolVersion
{
    ubyte major;
    ubyte minor;
}

/**
 * Each packet to be encrypted is first inserted into one of these structures.
 */
struct TLSPlaintext
{
    ContentType type;
    ProtocolVersion protocolVersion;
    ushort length;
}

struct Random
{
    uint gmtUnixTime;
    ubyte[28] randomBytes;
}

/**
 * Handshake message types (section 7.4)
 */
enum HandshakeType : ubyte
{
    helloRequest = 0,
    clientHello = 1,
    serverHello = 2,
    certificate = 11,
    serverKeyExchange = 12,
    certificateRequest = 13,
    serverHelloDone = 14,
    certificateVerify = 15,
    clientKeyExchange = 16,
    finished = 20
}

/**
 * Handshake record definition (section 7.4)
 */
struct Handshake
{
    ubyte type;
    uint length;       // 24 bits(!)
}

/**
 * Section 7.4.1.2
 */
struct ClientHello
{
    ProtocolVersion protocolVersion;
    Random random;
    Vector!ubyte sessionId;
    Vector!ushort cipherSuites;
}

struct ServerHello
{
    ProtocolVersion protocolVersion;
    Random random;
    ubyte session_id_length;
    ubyte[32] session_id; // technically, this len should be dynamic.
    ushort cipher_suite;
    ubyte compression_method;
}

void hello(ref TLSParameters parameters, ubyte[] encrypted)
{
    // The client sends the first message
    parameters.gotClientHello = false;
    if (!parameters.gotClientHello
     && receive_tls_msg(null, parameters, encrypted) < 0)
    {
        throw defaultAllocator.make!Alert(AlertDescription.handshakeFailure);
    }
    if (sendServerHello(parameters))
    {
        throw defaultAllocator.make!Alert(AlertDescription.handshakeFailure);
    }

    if (sendCertificate(parameters))
    {
        throw defaultAllocator.make!Alert(AlertDescription.handshakeFailure);
    }

    if (sendServerHelloDone(parameters))
    {
        throw defaultAllocator.make!Alert(AlertDescription.handshakeFailure);
    }
}

void tls_accept(ref TLSParameters parameters, ubyte[] encrypted = null)
{
    // Now the client should send a client key exchange, change cipher spec, and an
    // encrypted "finalize" message
    if (!parameters.peerFinished)
    {
        if (receive_tls_msg(null, parameters, encrypted) < 0)
        {
            throw defaultAllocator.make!Alert(AlertDescription.handshakeFailure);
        }
        else if (encrypted !is null)
        {
            return;
        }
    }

    // Finally, send server change cipher spec/finished message
    if (!(sendChangeCipherSpec(parameters)))
    {
        throw defaultAllocator.make!Alert(AlertDescription.handshakeFailure);
    }

    // This message will be encrypted using the newly negotiated keys
    if (!(sendFinished(parameters)))
    {
        throw defaultAllocator.make!Alert(AlertDescription.handshakeFailure);
    }
}

/**
 * Read a TLS packet off of the connection (assuming there's one waiting) and try
 * to update the security parameters based on the type of message received.  If
 * the read times out, or if an alert is received, return an error code; return 0
 * on success.
 * TODO - assert that the message received is of the type expected (for example,
 * if a server hello is expected but not received, this is a fatal error per
 * section 7.3).  returns -1 if an error occurred (this routine will have sent an
 * appropriate alert). Otherwise, return the number of bytes read if the packet
 * includes application data; 0 if the packet was a handshake.  -1 also indicates
 * that an alert was received.
 */
ptrdiff_t receive_tls_msg(ubyte[] buffer,
                          ref TLSParameters parameters,
                          ubyte[] encrypted)
{
    auto contentType = cast(ContentType) encrypted[0];

    // If a cipherspec is active, all of "encrypted" will be encrypted.
    // Must decrypt it before continuing.  This will change the message length
    // in all cases, since decrypting also involves verifying a MAC.
    const decrypted = decrypt(Vector!ubyte(encrypted), parameters.active_recv_parameters);

    ++parameters.active_recv_parameters.sequenceNumber;

    auto msgBuffer = decrypted[];

    switch (contentType) with (ContentType)
    {
        case handshake:
            Handshake handshake;

            handshake.type = msgBuffer.front;
            handshake.length = msgBuffer[1 .. 4].toHostOrder!uint();
            msgBuffer.popFrontN(4);

            switch (handshake.type) with (HandshakeType)
            {
                // Client-side messages.
                case serverHello:
                    parseServerHello(msgBuffer, parameters);
                    break;
                case certificate:
                    parseX509Chain(msgBuffer.get().ptr,
                                   handshake.length,
                                   &parameters.server_public_key);
                    break;
                case serverHelloDone:
                    parameters.serverHelloDone = true;
                    break;
                case finished:
                    parseFinished(msgBuffer, parameters);
                    break;

                // Server-side messages.
                case clientHello:
                    parseClientHello(msgBuffer, parameters);
                    break;
                case clientKeyExchange:
                    parseClientKeyExchange(msgBuffer, parameters);
                    break;

                default:
                    // Silently ignore any unrecognized types per section 6.
                    // However, out-of-order messages should result in a fatal
                    // alert per section 7.4.
            }

            parameters.md5_handshake_digest.put(decrypted[0 .. handshake.length + 4].get());
            parameters.sha1_handshake_digest.put(decrypted[0 .. handshake.length + 4].get());

            break;
        case alert:
            auto level = cast(AlertLevel) msgBuffer[0];
            auto description = cast(AlertDescription) msgBuffer[1];

            throw defaultAllocator.make!Alert(description, level);
        case changeCipherSpec:
            if (msgBuffer.front != 1)
            {
                throw make!Exception(defaultAllocator,
                                     "Received message ChangeCipherSpec, but type != 1");
            }
            else
            {
                parameters.pending_recv_parameters.sequenceNumber = 0;
                move(parameters.pending_recv_parameters, parameters.active_recv_parameters);
            }
            break;
        case applicationData:
            msgBuffer.copy(buffer);
            break;
        default:
            // Ignore content types not understood, per section 6 of the RFC.
    }

    return decrypted.length;
}

private void parseClientHello(ref Range!(const ubyte) msgBuffer,
                              ref TLSParameters parameters)
{
    int i;
    ClientHello hello;

    hello.protocolVersion.major = msgBuffer.front;
    msgBuffer.popFront();
    hello.protocolVersion.minor = msgBuffer.front;
    msgBuffer.popFront();

    hello.random.gmtUnixTime = msgBuffer[0 .. 4].toHostOrder!uint();
    msgBuffer[0 .. 4].copy(parameters.clientRandom[0 .. 4]);
    msgBuffer[4 .. 32].copy(hello.random.randomBytes[]);
    msgBuffer[4 .. 32].copy(parameters.clientRandom[4 .. 32]);
    msgBuffer.popFrontN(32);

    hello.sessionId = Vector!ubyte(msgBuffer.front);
    msgBuffer.popFront();
    if (hello.sessionId.length > 0)
    {
        msgBuffer[0 .. hello.sessionId.length].copy(hello.sessionId[]);
        msgBuffer.popFrontN(hello.sessionId.length);
        // TODO if this is non-empty, the client is trying to trigger a restart
    }

    const cipherSuitesLength = msgBuffer[0 .. 2].toHostOrder!ushort()
                             / ushort.sizeof;
    msgBuffer.popFrontN(2);
    hello.cipherSuites = Vector!ushort(cipherSuitesLength);

    foreach (ref cipherSuite; hello.cipherSuites[])
    {
        cipherSuite = msgBuffer[0 .. 2].toHostOrder!ushort();
        msgBuffer.popFrontN(2);
    }

    // Compression.
    if (msgBuffer[0] > 1 || msgBuffer[1] != 0)
    {
        throw defaultAllocator.make!Alert(AlertDescription.illegalParameter);
    }
    msgBuffer.popFrontN(2);

    for (i = 0; i < cipherSuitesLength; i++)
    {
        if (hello.cipherSuites[i] < CipherSuiteIdentifier.MAX_SUPPORTED_CIPHER_SUITE)
        {
            parameters.pending_recv_parameters.suite = CipherSuiteIdentifier.TLS_RSA_WITH_AES_128_CBC_SHA;
            parameters.pending_send_parameters.suite = CipherSuiteIdentifier.TLS_RSA_WITH_AES_128_CBC_SHA;
            break;
        }
    }

    if (i == CipherSuiteIdentifier.MAX_SUPPORTED_CIPHER_SUITE)
    {
        throw defaultAllocator.make!Alert(AlertDescription.illegalParameter);
    }

    parameters.gotClientHello = true;
    hello.random.randomBytes.copy(parameters.clientRandom[4 .. 32]);

    hello.sessionId.clear();
    hello.cipherSuites.clear();
}

int sendServerHello(ref TLSParameters parameters)
{
    ServerHello package_;
    time_t local_time;

    package_.protocolVersion.major = 3;
    package_.protocolVersion.minor = 2;
    time(&local_time);
    package_.random.gmtUnixTime = cast(uint) local_time;

    // TODO - actually make this random.
    // This is 28 bytes, but client random is 32 - the first four bytes of
    // "client random" are the GMT unix time computed above.
    NetworkOrder!4(package_.random.gmtUnixTime).copy(parameters.serverRandom[0 .. 4]);
    parameters.serverRandom[4 .. 32].copy(package_.random.randomBytes[]);

    package_.session_id_length = 0;
    package_.cipher_suite = parameters.pending_send_parameters.suite;
    package_.compression_method = 0;

    Vector!ubyte writeBuffer;
    writeBuffer.insertBack(package_.protocolVersion.major);
    writeBuffer.insertBack(package_.protocolVersion.minor);

    writeBuffer.insertBack(NetworkOrder!4(package_.random.gmtUnixTime));
    writeBuffer.insertBack(package_.random.randomBytes);

    writeBuffer.insertBack(package_.session_id_length);

    writeBuffer.insertBack(NetworkOrder!2(package_.cipher_suite));
    writeBuffer.insertBack(package_.compression_method);

    return sendHandshakeMessage(HandshakeType.serverHello, writeBuffer.get(), parameters);
}

int sendCertificate(ref TLSParameters parameters)
{
    // Allocate enough space for the certificate file, plus 2 3-byte length
    // entries.
    const certificateLength = parameters.handshakeParameters.certificateChain.length;
    auto send_buffer = Vector!ubyte(certificateLength + 6);

    NetworkOrder!3(certificateLength + 3).copy(send_buffer[0 .. 3]);
    NetworkOrder!3(certificateLength).copy(send_buffer[3 .. 6]);

    parameters.handshakeParameters.certificateChain.copy(send_buffer[6 .. $]);

    sendHandshakeMessage(HandshakeType.certificate, send_buffer.get(), parameters);

    return 0;
}

int sendServerHelloDone(ref TLSParameters parameters)
{
    return sendHandshakeMessage(HandshakeType.serverHelloDone, null, parameters);
}

private int sendAlert(AlertDescription alertCode, ref TLSParameters parameters)
{
    ubyte[2] buffer;

    // TODO support warnings
    buffer[0] = AlertLevel.fatal;
    buffer[1] = cast(ubyte) alertCode;

    return sendMessage(ContentType.alert, buffer, parameters);
}

private int sendChangeCipherSpec(ref TLSParameters parameters)
{
    ubyte[1] send_buffer;
    send_buffer[0] = 1;
    sendMessage(ContentType.changeCipherSpec, send_buffer, parameters);

    // Per 6.1: The sequence number must be set to zero whenever a connection
    // state is made the active state... the first record which is transmitted
    // under a particular connection state should use sequence number 0.
    parameters.pending_send_parameters.sequenceNumber = 0;
    move(parameters.pending_send_parameters, parameters.active_send_parameters);

    return 1;
}

private int sendFinished(ref TLSParameters parameters)
{
    auto verifyData = computeVerifyData("server finished", parameters);
    sendHandshakeMessage(HandshakeType.finished, verifyData[], parameters);

    return 1;
}

private void parseFinished(ref Range!(const ubyte) msgBuffer,
                           ref TLSParameters parameters)
{
    auto verifyData = computeVerifyData("client finished", parameters);

    parameters.peerFinished = true;

    if (!equal(msgBuffer[0 .. verifyData.length], verifyData[]))
    {
        throw defaultAllocator.make!Alert(AlertDescription.illegalParameter);
    }
    msgBuffer.popFrontN(verifyData.length);
}

private ubyte[12] computeVerifyData(const char[] finishedLabel,
                                    ref TLSParameters parameters)
{
    ubyte[36] handshakeHash;
    typeof(return) verifyData;

    computeHandshakeHash(parameters, handshakeHash);

    prf(parameters.masterSecret,
        finishedLabel,
        handshakeHash[],
        verifyData[]);

    return verifyData;
}

private void parseServerHello(ref Range!(const ubyte) msgBuffer,
                              ref TLSParameters parameters)
{
    ServerHello hello;

    hello.protocolVersion.major = msgBuffer.front;
    msgBuffer.popFront();
    hello.protocolVersion.minor = msgBuffer.front;
    msgBuffer.popFront();

    hello.random.gmtUnixTime = msgBuffer[0 .. 4].toHostOrder!uint();
    msgBuffer[0 .. 4].copy(parameters.serverRandom[0 .. 4]);
    msgBuffer.popFrontN(4);
    msgBuffer[0 .. 28].copy(hello.random.randomBytes[]);
    msgBuffer[0 .. 28].copy(parameters.serverRandom[4 .. 32]);
    msgBuffer.popFrontN(28);

    hello.session_id_length = msgBuffer.front;
    msgBuffer.popFront();
    msgBuffer[0 .. hello.session_id_length].copy(hello.session_id[]);
    msgBuffer.popFrontN(hello.session_id_length);

    hello.cipher_suite = msgBuffer[0 .. 2].toHostOrder!ushort();
    msgBuffer.popFrontN(2);

    // TODO check that these values were actually in the client hello list.
    parameters.pending_recv_parameters.suite = cast(CipherSuiteIdentifier) hello.cipher_suite;
    parameters.pending_send_parameters.suite = cast(CipherSuiteIdentifier) hello.cipher_suite;

    hello.compression_method = msgBuffer.front;
    msgBuffer.popFront();
    if (hello.compression_method != 0)
    {
        throw defaultAllocator.make!Alert(AlertDescription.illegalParameter);
    }

    // TODO - abort if there's more data here than in the spec (per section 7.4.1.2,
    // forward compatibility note)
    // TODO - abort if version < 3.1 with "protocol_version" alert error
}

/*
 * Decrypt a message and verify its MAC according to the active cipher spec
 * (as given by "parameters").  Free the space allocated by encrypted message
 * and allocate new space for the decrypted message (if decrypting is "identity",
 * then decrypted will point to encrypted).  The caller must always issue a
 * "free decrypted_message".
 * Return the length of the message, or -1 if the MAC doesn't verify.  The return
 * value will almost always be different than "encrypted.length", since it strips
 * off the MAC if present as well as bulk cipher padding (if a block cipher
 * algorithm is being used).
 */
private Vector!ubyte decrypt(const Vector!ubyte encrypted,
                             ref ProtectionParameters parameters)
{
    Vector!ubyte decrypted;

    if (parameters.cipherSuite.bulkCipher !is null)
    {
        auto encryptedBuffer = Vector!ubyte(encrypted[21 .. $]);
        encrypted[5 .. 21].copy(parameters.iv[]);
        decrypted.length = encryptedBuffer.length;

        parameters.cipherSuite.bulkCipher.start(Direction.decryption, parameters.iv);
        parameters.cipherSuite.bulkCipher.key = parameters.key;
        parameters.cipherSuite.bulkCipher.process(encryptedBuffer, decrypted);
        parameters.cipherSuite.bulkCipher.finish();

        // Strip off padding.
        decrypted.length = encryptedBuffer.length - decrypted[$ - 1] - 1;
    }
    else
    {
        // Do nothing, no bulk cipher algorithm chosen.
        decrypted = encrypted[5 .. $];
    }

    // Now, verify the MAC (if the active cipher suite includes one).
    if (parameters.cipherSuite.mac !is null)
    {
        auto msg = decrypted[0 .. $ - parameters.cipherSuite.mac.digestLength];

        // Allocate enough space for the 8-byte sequence number, the TLSPlainText
        // header, and the fragment (e.g. the decrypted message).
        auto macBuffer = Vector!ubyte(13 + msg.length);
        copy(NetworkOrder!8(parameters.sequenceNumber), macBuffer[0 .. 8]);

        // Copy first three bytes of header; last two bytes reflected the
        // message length, with MAC attached.  Since the MAC was computed
        // by the other side before it was attached (obviously), that MAC
        // was computed using the original length.
        copy(encrypted[0 .. 3], macBuffer[8 .. 11]);
        copy(NetworkOrder!2(msg.length), macBuffer[11 .. 13]);
        macBuffer[13 .. $] = msg;

        parameters.cipherSuite.mac.start(parameters.macSecret);
        parameters.cipherSuite.mac.put((cast(const) macBuffer)[]);
        auto hash = parameters.cipherSuite.mac.finish();

        if (hash != decrypted[msg.length .. $])
        {
            throw defaultAllocator.make!Alert(AlertDescription.badRecordMAC);
        }
        decrypted.length = msg.length;
    }

    return decrypted;
}

/**
 * By the time this is called, "msgBuffer" points at an RSA encrypted (unless
 * RSA isn't used for key exchange) premaster secret.  All this routine has to
 * do is decrypt it.  See "privkey.c" for details.
 * TODO expand this to support Diffie-Hellman key exchange
 */
private void parseClientKeyExchange(ref Range!(const ubyte) msgBuffer,
                                    ref TLSParameters parameters)
{
    ubyte* buffer;
    int buffer_length;
    ubyte[] premasterSecret;
    rsa_key private_key;

    parse_private_key(private_key, parameters.handshakeParameters.key.ptr, parameters.handshakeParameters.key.length);

    // Skip over the two length bytes, since length is already known anyway
    premasterSecret = rsa_decrypt(msgBuffer[2 .. $].get(), private_key);
    msgBuffer.popFrontN(msgBuffer.length);

    if (premasterSecret is null)
    {
        throw defaultAllocator.make!Alert(AlertDescription.illegalParameter);
    }

    // Now use the premaster secret to compute the master secret.  Don't forget
    // that the first two bytes of the premaster secret are the version 0x03 0x01
    // These are part of the premaster secret (8.1.1 states that the premaster
    // secret for RSA is exactly 48 bytes long).
    computeMasterSecret(premasterSecret, parameters);

    calculateKeys(parameters);
}

/*
 6.3: Compute a key block, including MAC secrets, keys, and IVs for client & server
Notice that the seed is server random followed by client random (whereas for master
secret computation, it's client random followed by server random). Sheesh!
 */
private void calculateKeys(ref TLSParameters parameters)
{
    // XXX assuming send suite & recv suite will always be the same
    CipherSuite *suite = &parameters.pending_send_parameters.cipherSuite;
    char[13] label = "key expansion";
    const keyLength = suite.bulkCipher.cipher.keyLength;
    const blockLength = suite.bulkCipher.cipher.blockLength;
    const keyBlockLength = suite.hash_size * 2 + keyLength * 2 + blockLength * 2;
    ubyte[parameters.clientRandom.length + parameters.serverRandom.length] seed;
    auto keyBlock = Vector!ubyte(keyBlockLength);
    auto keyBlockRange = keyBlock[];

    parameters.serverRandom[].copy(seed[0 .. parameters.serverRandom.length]);
    parameters.clientRandom[].copy(seed[parameters.serverRandom.length .. $]);

    prf(parameters.masterSecret, label, seed, keyBlock.get());

    parameters.pending_send_parameters.macSecret.length = suite.hash_size;
    parameters.pending_recv_parameters.macSecret.length = suite.hash_size;
    parameters.pending_send_parameters.key.length = keyLength;
    parameters.pending_recv_parameters.key.length = keyLength;

    keyBlockRange[0 .. suite.hash_size].copy(parameters.pending_recv_parameters.macSecret[]);
    keyBlockRange.popFrontN(suite.hash_size);
    keyBlockRange[0 .. suite.hash_size].copy(parameters.pending_send_parameters.macSecret[]);
    keyBlockRange.popFrontN(suite.hash_size);

    keyBlockRange[0 .. keyLength].copy(parameters.pending_recv_parameters.key[]);
    keyBlockRange.popFrontN(keyLength);
    keyBlockRange[0 .. keyLength].copy(parameters.pending_send_parameters.key[]);
    keyBlockRange.popFrontN(keyLength);

    parameters.pending_recv_parameters.iv = Vector!ubyte(blockLength);
    keyBlockRange[0 .. blockLength].copy(parameters.pending_recv_parameters.iv[]);
    keyBlockRange.popFrontN(blockLength);

    parameters.pending_send_parameters.iv = Vector!ubyte(blockLength);
    keyBlockRange[0 .. blockLength].copy(parameters.pending_send_parameters.iv[]);
}

private int sendHandshakeMessage(HandshakeType type,
                                 const ubyte[] message,
                                 ref TLSParameters parameters)
{
    auto sendBuffer = Vector!ubyte(message.length + 4);
    auto record = Handshake(type, cast(uint) message.length);

    sendBuffer[0] = record.type;
    NetworkOrder!3(record.length).copy(sendBuffer[1 .. 4]);
    message.copy(sendBuffer[4 .. $]);

    parameters.md5_handshake_digest.put(sendBuffer.get());
    parameters.sha1_handshake_digest.put(sendBuffer.get());

    return sendMessage(ContentType.handshake, sendBuffer.get(), parameters);
}

/**
 * Turn the premaster secret into an actual master secret (the
 * server side will do this concurrently) as specified in section 8.1:
 * masterSecret = prf(premasterSecret, "master secret", ClientHello.random + ServerHello.random);
 * (premasterSecret, parameters);
 * Note that, with DH, the master secret length is determined by the generator (p)
 * value.
 */
private void computeMasterSecret(ref const ubyte[] premasterSecret,
                                 ref TLSParameters parameters)
{
    char[13] label = "master secret";
    ubyte[parameters.clientRandom.length + parameters.serverRandom.length] seed;

    parameters.clientRandom[].copy(seed[0 .. parameters.clientRandom.length]);
    parameters.serverRandom[].copy(seed[parameters.clientRandom.length .. $]);

    prf(premasterSecret, label, seed[], parameters.masterSecret);
}

private int sendMessage(ContentType contentType,
                        const(ubyte)[] content,
                        ref TLSParameters parameters)
{
    TLSPlaintext header;
    Vector!ubyte sendBuffer;
    int sendBufferSize;
    int paddingLength;
    CipherSuite* active_suite = &parameters.active_send_parameters.cipherSuite;
    Vector!ubyte hash;

    header.type = contentType;
    header.protocolVersion.major = TLS_VERSION_MAJOR;
    header.protocolVersion.minor = TLS_VERSION_MINOR;

    if (active_suite.mac !is null)
    {
        // Allocate enough space for the 8-byte sequence number, the 5-byte pseudo
        // header, and the content.
        auto macBuffer = Vector!ubyte(13 + content.length);

        copy(NetworkOrder!8(parameters.active_send_parameters.sequenceNumber),
             macBuffer[0 .. 8]);

        // These will be overwritten below
        macBuffer[8] = header.type;
        macBuffer[9] = header.protocolVersion.major;
        macBuffer[10] = header.protocolVersion.minor;
        copy(NetworkOrder!2(content.length), macBuffer[11 .. 13]);

        copy(content, macBuffer[13 .. $]);
        active_suite.mac.start(parameters.active_send_parameters.macSecret);
        active_suite.mac.put((cast(const) macBuffer)[]);
        hash = active_suite.mac.finish();
    }

    sendBufferSize = cast(int) content.length + active_suite.hash_size;

    if (active_suite.bulkCipher !is null)
    {
        paddingLength = active_suite.bulkCipher.cipher.blockLength -
            (sendBufferSize % active_suite.bulkCipher.cipher.blockLength);
        sendBufferSize += paddingLength;
    }

    // Add space for the header, but only after computing padding
    sendBufferSize += 5;
    sendBuffer.length = sendBufferSize;

    if (hash.length > 0)
    {
        hash.get().copy(sendBuffer[content.length + 5 .. $]);
    }

    if (paddingLength > 0)
    {
        ubyte* padding;
        for (padding = sendBuffer.get().ptr + sendBufferSize - 1;
                padding > (sendBuffer.get().ptr + (sendBufferSize - paddingLength - 1));
                padding--)
        {
            *padding = cast(ubyte) (paddingLength - 1);
        }
    }

    sendBuffer[0] = header.type;
    sendBuffer[1] = header.protocolVersion.major;
    sendBuffer[2] = header.protocolVersion.minor;
    if (active_suite.bulkCipher !is null)
    {
        NetworkOrder!2(16 + content.length + active_suite.hash_size + paddingLength).copy(sendBuffer[3 .. 5]);
    }
    else
    {
        NetworkOrder!2(content.length + active_suite.hash_size + paddingLength).copy(sendBuffer[3 .. 5]);
    }
    content.copy(sendBuffer[5 .. $]);

    if (active_suite.bulkCipher !is null)
    {
        auto encryptedBuffer = Vector!ubyte(sendBufferSize - 5);
        auto decrypted = Vector!ubyte(sendBuffer[5 .. $]);
        parameters.active_send_parameters.iv[].fill(cast(ubyte) 0);

        sendBuffer[5 .. $].copy(encryptedBuffer[]);

        sendBufferSize += 16;
        sendBuffer.length = sendBufferSize;

        active_suite.bulkCipher.start(Direction.encryption, parameters.active_send_parameters.iv);
        active_suite.bulkCipher.key = parameters.active_send_parameters.key;
        active_suite.bulkCipher.process(decrypted, encryptedBuffer);
        active_suite.bulkCipher.finish();

        sendBuffer[5 .. 21].fill(cast(ubyte) 0);
        encryptedBuffer[].copy(sendBuffer[21 .. $]);
    }

    parameters.sender(sendBuffer[0 .. sendBufferSize].get());

    ++parameters.active_send_parameters.sequenceNumber;

    return 0;
}

private void computeHandshakeHash(ref TLSParameters parameters, ref ubyte[36] handshakeHash)
{
    // "cheating". Copy the handshake digests into local memory (and change
    // the hash pointer) so that we can finalize twice (again in "recv")
    auto tmp_md5_handshake_digest = parameters.md5_handshake_digest;
    auto tmp_sha1_handshake_digest = parameters.sha1_handshake_digest;

    auto md5_hash = tmp_md5_handshake_digest.finish();
    auto sha1_hash = tmp_sha1_handshake_digest.finish();

    md5_hash[0 .. 16].copy(handshakeHash[]);
    sha1_hash[0 .. 20].copy(handshakeHash[16 .. $]);
}

int tls_send(const(ubyte)[] appData, ref TLSParameters parameters)
{
    return sendMessage(ContentType.applicationData, appData, parameters);
}

int tls_shutdown(ref TLSParameters parameters)
{
    sendAlert(AlertDescription.closeNotify, parameters);
    return 1;
}

/**
 * P_MD5 or P_SHA, depending on the value of the "new_digest" function
 * pointer.
 * HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
 * where + indicates concatenation and A(0) = seed, A(i) =
 * HMAC_hash(secret, A(i - 1))
 */
private void pHash(H)(const ubyte[] key,
                      const ubyte[] seed_,
                      ubyte[] output)
    if (hasBlockSize!H)
{
    auto secret = Vector!ubyte(key);
    auto seed = const Vector!ubyte(seed_);

    auto A_ctx_ = defaultAllocator.make!(HMAC!H);
    auto h = defaultAllocator.make!(HMAC!H);

    A_ctx_.start(secret);
    A_ctx_.put(seed[]);
    auto A_hash = A_ctx_.finish();

    // length of the hash code in bytes
    auto A = Vector!ubyte(A_hash.length + seed.length);
    copy(A_hash[], A[0 .. A_hash.length]);
    copy(seed[], A[A_hash.length .. $]);

    auto outputPtr = output;
    while (outputPtr.length > 0)
    {
        // HMAC_Hash(secret, A(i) + seed)
        h.start(secret);
        h.put((cast(const) A)[]);
        auto h_hash = h.finish();
        auto adv = min(h_hash.length, outputPtr.length);
        copy(h_hash[0 .. adv], outputPtr[0 .. adv]);
        outputPtr = outputPtr[adv .. $];

        // Set A for next iteration
        // A(i) = HMAC_hash(secret, A(i - 1))
        A_ctx_.start(secret);
        A_ctx_.put((cast(const) A[0 .. A_hash.length])[]);
        A_hash = A_ctx_.finish();
        A[0 .. A_hash.length] = A_hash[];
    }

    defaultAllocator.dispose(h);
    defaultAllocator.dispose(A_ctx_);
}

/**
 * P_MD5(S1, label + seed) XOR P_SHA1(S2, label + seed);
 * where S1 & S2 are the first & last half of secret
 * and label is an ASCII string.  Ignore the null terminator.
 *
 * output must already be allocated.
 */
void prf(const ubyte[] secret,
         const char[] label,
         const ubyte[] seed,
         ubyte[] output)
{
    size_t half_secret_len;
    auto sha1_out = Vector!ubyte(output.length);
    auto concat = Vector!ubyte(label.length + seed.length);

    label.copy(concat[0 .. label.length]);
    seed.copy(concat[label.length .. $]);

    half_secret_len = (secret.length / 2) + (secret.length % 2);
    pHash!MD5(secret[0 .. half_secret_len], concat.get(), output);
    pHash!SHA1(secret[secret.length / 2 .. $], concat.get(), sha1_out.get());

    for (auto i = 0; i < output.length; ++i)
    {
        output[i] ^= sha1_out[i];
    }
}
