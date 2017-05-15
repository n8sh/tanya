/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Copyright: Eugene Wissner 2017.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:info@caraus.de, Eugene Wissner)
 */
module tanya.crypto.x509;

import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.string;
import core.stdc.time;
import std.digest.digest;
import std.digest.md;
import std.digest.sha;
import tanya.container.vector;
import tanya.crypto.rsa;
import tanya.encoding.asn1;
import tanya.math.mp;
import tanya.memory;

enum algorithmIdentifier
{
    rsa,
}

enum signatureAlgorithmIdentifier
{
    md5WithRSAEncryption,
    shaWithRSAEncryption,
}

/**
 * A name (or "distninguishedName") is a list of attribute-value pairs.
 * Instead of keeping track of all of them, just keep track of
 * the most interesting ones.
 */
struct name
{
    ubyte* idAtCountryName;
    ubyte* idAtStateOrProvinceName;
    ubyte* idAtLocalityName;
    ubyte* idAtOrganizationName;
    ubyte* idAtOrganizationalUnitName;
    ubyte* idAtCommonName;
}

struct validity_period
{
    // TODO deal with the "utcTime" or "GeneralizedTime" choice.
    time_t notBefore;
    time_t notAfter;
}

alias uniqueIdentifier = Integer;

struct public_key_info
{
    algorithmIdentifier algorithm;
    rsa_key rsa_public_key;
}

alias objectIdentifier = Integer;

struct x509_certificate
{
    int version_;
    Integer serialNumber; // This can be much longer than a 4-byte long allows
    signatureAlgorithmIdentifier signature;
    name issuer;
    validity_period validity;
    name subject;
    public_key_info subjectPublicKeyInfo;
    uniqueIdentifier issueUniqueId;
    uniqueIdentifier subjectUniqueId;
    int certificate_authority; // 1 if this is a CA, 0 if not
}

struct signed_x509_certificate
{
    x509_certificate tbsCertificate;
    uint* hash; // hash code of tbsCertificate
    size_t hash_len;
    signatureAlgorithmIdentifier algorithm;
    Integer rsa_signature_value;
}

void init_x509_certificate(signed_x509_certificate *certificate)
{
    certificate.tbsCertificate.serialNumber = 1;
    memset(&certificate.tbsCertificate.issuer, 0, name.sizeof);
    memset(&certificate.tbsCertificate.subject, 0, name.sizeof);
    certificate.tbsCertificate.subjectPublicKeyInfo.rsa_public_key.modulus = 0;
    certificate.tbsCertificate.subjectPublicKeyInfo.rsa_public_key.exponent = 0;
    certificate.rsa_signature_value = 0;
    certificate.tbsCertificate.certificate_authority = 0;
}

private void free_x500_name(name* x500_name)
{
    if (x500_name.idAtCountryName)
    {
        free(x500_name.idAtCountryName);
    }
    if (x500_name.idAtStateOrProvinceName)
    {
        free(x500_name.idAtStateOrProvinceName);
    }
    if (x500_name.idAtLocalityName)
    {
        free(x500_name.idAtLocalityName);
    }
    if (x500_name.idAtOrganizationName)
    {
        free(x500_name.idAtOrganizationName);
    }
    if (x500_name.idAtOrganizationalUnitName)
    {
        free(x500_name.idAtOrganizationalUnitName);
    }
    if (x500_name.idAtCommonName)
    {
        free(x500_name.idAtCommonName);
    }
}

void free_x509_certificate(signed_x509_certificate *certificate)
{
    destroy(certificate.tbsCertificate.serialNumber);
    free_x500_name(&certificate.tbsCertificate.issuer);
    free_x500_name(&certificate.tbsCertificate.subject);
    destroy(certificate.tbsCertificate.subjectPublicKeyInfo.rsa_public_key.modulus);
    destroy(certificate.tbsCertificate.subjectPublicKeyInfo.rsa_public_key.exponent);
    destroy(certificate.rsa_signature_value);
}

int parse_x509_certificate(const(ubyte)* buffer,
                           const uint certificate_length,
                           signed_x509_certificate* parsed_certificate)
{
    asn1struct certificate;
    asn1struct *tbsCertificate;
    asn1struct *algorithmIdentifier;
    asn1struct *signatureValue;

    // First, read the whole thing into a traversable ASN.1 structure
    asn1parse(buffer, certificate_length, &certificate);

    tbsCertificate = certificate.children;

    algorithmIdentifier = tbsCertificate.next;
    signatureValue = algorithmIdentifier.next;
    if (parse_tbs_certificate(&parsed_certificate.tbsCertificate, tbsCertificate))
    {
        fprintf(stderr, "Error trying to parse TBS certificate\n");
        return 42;
    }
    if (parse_algorithm_identifier(&parsed_certificate.algorithm, algorithmIdentifier))
    {
        return 42;
    }

    switch (parsed_certificate.algorithm) with (signatureAlgorithmIdentifier)
    {
        case md5WithRSAEncryption:
        case shaWithRSAEncryption:
            if (parse_rsa_signature_value(parsed_certificate, signatureValue))
            {
                return 42;
            }
            break;
        default:
            break;
    }

    auto hash = defaultAllocator.make!(Vector!ubyte);
    switch (parsed_certificate.algorithm) with (signatureAlgorithmIdentifier)
    {
        case md5WithRSAEncryption:
            *hash = Vector!ubyte(digest!MD5(tbsCertificate.data[0 .. tbsCertificate.length]));
            break;
        case shaWithRSAEncryption:
            *hash = Vector!ubyte(digest!SHA1(tbsCertificate.data[0 .. tbsCertificate.length]));
            break;
        default:
            break;
    }

    parsed_certificate.hash = (cast(uint[]) hash.get()).ptr;
    parsed_certificate.hash_len = hash.length / uint.sizeof;

    asn1free(&certificate);

    return 0;
}

private int parse_tbs_certificate(x509_certificate* target,
                                  asn1struct* source)
{
    asn1struct* version_;
    asn1struct* serialNumber;
    asn1struct* signatureAlgorithmIdentifier;
    asn1struct* issuer;
    asn1struct* validity;
    asn1struct* subject;
    asn1struct* publicKeyInfo;
    asn1struct* extensions;

    // Figure out if there's an explicit version or not; if there is, then
    // everything else "shifts down" one spot.
    version_ = source.children;

    if (version_.tag == 0 && version_.tagClass == TagClass.contextSpecific)
    {
        asn1struct* versionNumber = version_.children;

        // This will only ever be one byte; safe
        target.version_ = (*versionNumber.data) + 1;
        serialNumber = version_.next;
    }
    else
    {
        target.version_ = 1; // default if not provided
        serialNumber = version_;
    }

    signatureAlgorithmIdentifier = serialNumber.next;
    issuer = signatureAlgorithmIdentifier.next;
    validity = issuer.next;
    subject = validity.next;

    publicKeyInfo = subject.next;
    extensions = publicKeyInfo.next;

    if (parse_huge(target.serialNumber, serialNumber))
    {
        return 2;
    }
    if (parse_algorithm_identifier(&target.signature, signatureAlgorithmIdentifier))
    {
        return 3;
    }
    if (parse_name(&target.issuer, issuer))
    {
        return 4;
    }
    if (parse_validity(&target.validity, validity))
    {
        return 5;
    }
    if (parse_name(&target.subject, subject))
    {
        return 6;
    }
    if (parse_public_key_info(&target.subjectPublicKeyInfo, publicKeyInfo))
    {
        return 7;
    }
    if (extensions)
    {
        if (parse_extensions(target, extensions))
        {
            return 8;
        }
    }

    return 0;
}

private int parse_huge(ref Integer target, asn1struct* source)
{
    target = Integer(Sign.positive, cast(ubyte[]) source[0 .. source.length]);
    return 0;
}

private const ubyte[8] OID_md5WithRSA = [
    0x2A, 0x86, 0x48, 0xF7, 0x0D, 0x01, 0x01, 0x04
];

private const ubyte[8] OID_sha1WithRSA = [
    0x2A, 0x86, 0x48, 0xF7, 0x0D, 0x01, 0x01, 0x05
];

private int parse_algorithm_identifier(signatureAlgorithmIdentifier* target,
                                       asn1struct* source)
{
    asn1struct* oid = source.children;

    if (!memcmp(oid.data, OID_md5WithRSA.ptr, oid.length))
    {
        *target = signatureAlgorithmIdentifier.md5WithRSAEncryption;
    }
    else if (!memcmp(oid.data, OID_sha1WithRSA.ptr, oid.length))
    {
        *target = signatureAlgorithmIdentifier.shaWithRSAEncryption;
    }
    else
    {
        int i;
        fprintf(stderr, "Unsupported or unrecognized algorithm identifier OID");
        for (i = 0; i < oid.length; i++)
        {
            fprintf(stderr, "%.02x", oid.data[i]);
        }
        fprintf(stderr, "\n");
        return 2;
    }

    return 0;
}

private ubyte[3] OID_idAtCommonName = [ 0x55, 0x04, 0x03 ];
private ubyte[3] OID_idAtCountryName = [ 0x55, 0x04, 0x06 ];
private ubyte[3] OID_idAtLocalityName = [ 0x55, 0x04, 0x07 ];
private ubyte[3] OID_idAtStateOrProvinceName = [ 0x55, 0x04, 0x08 ];
private ubyte[3] OID_idAtOrganizationName = [ 0x55, 0x04, 0x0A ];
private ubyte[3] OID_idAtOrganizationalUnitName = [ 0x55, 0x04, 0x0B ];

/**
 * Name parsing is a bit different. Loop through all of the
 * children of the source, each of which is going to be a struct containing
 * an OID and a value. If the OID is recognized, copy its contents
 * to the correct spot in "target". Otherwise, ignore it.
 */
int parse_name(name* target, asn1struct* source)
{
    asn1struct* typeValuePair;
    asn1struct* typeValuePairSequence;
    asn1struct* type;
    asn1struct* value;

    target.idAtCountryName = null;
    target.idAtStateOrProvinceName = null;
    target.idAtLocalityName = null;
    target.idAtOrganizationName = null;
    target.idAtOrganizationalUnitName = null;
    target.idAtCommonName = null;

    typeValuePair = source.children;
    while (typeValuePair)
    {
        typeValuePairSequence = typeValuePair.children;
        type = typeValuePairSequence.children;
        value = type.next;

        if (!memcmp(type.data, OID_idAtCountryName.ptr, type.length))
        {
            target.idAtCountryName = cast(ubyte*) malloc(value.length + 1);
            memcpy(target.idAtCountryName, value.data, value.length);
            target.idAtCountryName[value.length] = 0;
        }
        else if (!memcmp(type.data, OID_idAtStateOrProvinceName.ptr, type.length))
        {
            target.idAtStateOrProvinceName = cast(ubyte*) malloc(value.length + 1);
            memcpy(target.idAtStateOrProvinceName, value.data, value.length);
            target.idAtStateOrProvinceName[value.length] = 0;
        }
        else if (!memcmp(type.data, OID_idAtLocalityName.ptr, type.length))
        {
            target.idAtLocalityName = cast(ubyte*) malloc(value.length + 1);
            memcpy(target.idAtLocalityName, value.data, value.length);
            target.idAtLocalityName[value.length] = 0;
        }
        else if (!memcmp(type.data, OID_idAtOrganizationName.ptr, type.length))
        {
            target.idAtOrganizationName = cast(ubyte*) malloc(value.length + 1);
            memcpy(target.idAtOrganizationName, value.data, value.length);
            target.idAtOrganizationName[value.length] = 0;
        }
        else if (!memcmp(type.data, OID_idAtOrganizationalUnitName.ptr, type.length))
        {
            target.idAtOrganizationalUnitName = cast(ubyte*) malloc(value.length + 1);
            memcpy(target.idAtOrganizationalUnitName, value.data, value.length);
            target.idAtOrganizationalUnitName[value.length] = 0;
        }
        else if (!memcmp(type.data, OID_idAtCommonName.ptr, type.length))
        {
            target.idAtCommonName = cast(ubyte*) malloc(value.length + 1);
            memcpy(target.idAtCommonName, value.data, value.length);
            target.idAtCommonName[value.length] = 0;
        }
        else
        {
            int i;

            // This is just advisory - NOT a problem
            printf("Skipping unrecognized or unsupported name token OID of ");
            for (i = 0; i < type.length; i++)
            {
                printf("%x02x ", type.data[i]);
            }
            printf("\n");
        }
        typeValuePair = typeValuePair.next;
    }

    return 0;
}

private int parse_validity(validity_period* target, asn1struct* source)
{
    asn1struct* not_before;
    asn1struct* not_after;
    tm not_before_tm;
    tm not_after_tm;

    not_before = source.children;

    not_after = not_before.next;
    // Convert time instances into time_t
    if (sscanf(cast(char*) not_before.data, "%2d%2d%2d%2d%2d%2d",
                &not_before_tm.tm_year, &not_before_tm.tm_mon, &not_before_tm.tm_mday,
                &not_before_tm.tm_hour, &not_before_tm.tm_min, &not_before_tm.tm_sec) < 6)
    {
        fprintf(stderr, "Error parsing not before; malformed date.");
        return 6;
    }
    if (sscanf(cast(char*) not_after.data, "%2d%2d%2d%2d%2d%2d",
                &not_after_tm.tm_year, &not_after_tm.tm_mon, &not_after_tm.tm_mday,
                &not_after_tm.tm_hour, &not_after_tm.tm_min, &not_after_tm.tm_sec) < 6)
    {
        fprintf(stderr, "Error parsing not after; malformed date.");
        return 7;
    }

    not_before_tm.tm_year += 100;
    not_after_tm.tm_year += 100;
    not_before_tm.tm_mon -= 1;
    not_after_tm.tm_mon -= 1;

    // TODO account for TZ information on end
    target.notBefore = mktime(&not_before_tm);
    target.notAfter = mktime(&not_after_tm);

    return 0;
}

private const ubyte[9] OID_RSA = [
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
];
private const ubyte[7] OID_DH = [
    0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01
];
// A.K.A. secp192R1, AKA NIST P-192
private const ubyte[8] OID_PRIME192V1 = [
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01
];

private int parse_public_key_info(public_key_info *target,
                                  asn1struct *source )
{
    asn1struct* oid;
    asn1struct* public_key;
    asn1struct public_key_value;

    if (!validate_node(source, TagType.sequence, 2, "public key info"))
    {
        return 1;
    }

    if (!validate_node(source.children, TagType.sequence, 1, "public key OID"))
    {
        return 2;
    }

    oid = source.children.children;
    public_key = source.children.next;

    if (!validate_node(oid, TagType.objectIdentifier, 0, "public key OID"))
    {
        return 3;
    }

    if (!validate_node(public_key, TagType.bitString, 0, "public key info"))
    {
        return 4;
    }

    // The public key is a bit string encoding yet another ASN.1 DER-encoded
    // value - need to parse *that* here
    // Skip over the "0" byte in the public key.
    if (asn1parse(public_key.data + 1, public_key.length - 1, &public_key_value))
    {
        fprintf(stderr, "Error; public key node is malformed (not ASN.1 DER-encoded)\n");
        return 5;
    }

    if (!memcmp(oid.data, &OID_RSA, OID_RSA.sizeof))
    {
        target.algorithm = algorithmIdentifier.rsa;

        if (!validate_node(&public_key_value, TagType.sequence, 2, "RSA public key value"))
        {
            return 6;
        }

        parse_huge(target.rsa_public_key.modulus, public_key_value.children);
        parse_huge(target.rsa_public_key.exponent, public_key_value.children.next);
    }
    else
    {
        fprintf(stderr, "Error; unsupported OID in public key info.\n");
        return 7;
    }

    asn1free(&public_key_value);

    return 0;
}

private int parse_extensions(x509_certificate* certificate, asn1struct* source)
{
    // Parse each extension; if one is recognized, update the certificate
    // in some way
    source = source.children.children;
    while (source)
    {
        if (parse_extension(certificate, source))
        {
            return 1;
        }
        source = source.next;
    }

    return 0;
}

private const ubyte[3] OID_keyUsage = [ 0x55, 0x1D, 0x0F ];
private enum BIT_CERT_SIGNER = 5;

private int parse_extension(x509_certificate* certificate, asn1struct* source)
{
    asn1struct* oid;
    asn1struct* critical;
    asn1struct* data;

    oid = source.children;
    critical = oid.next;
    if (critical.tag == TagType.boolean)
    {
        data = critical.next;
    }
    else
    {
        // critical defaults to false
        data = critical;
        critical = null;
    }
    if (!memcmp(oid.data, OID_keyUsage.ptr, oid.length))
    {
        asn1struct key_usage_bit_string;
        asn1parse(data.data, data.length, &key_usage_bit_string);
        if (asn1_get_bit( key_usage_bit_string.length,
                    key_usage_bit_string.data,
                    BIT_CERT_SIGNER))
        {
            certificate.certificate_authority = 1;
        }
        asn1free(&key_usage_bit_string);
    }

    // TODO recognize and parse extensions - there are several
    return 0;
}

int asn1_get_bit(const int length, const ubyte* bit_string, const int bit)
{
    if (bit > ((length - 1) * 8))
    {
        return 0;
    }
    else
    {
        return bit_string[1 + (bit / 8)] & (0x80 >> (bit & 8));
    }
}

private int parse_rsa_signature_value(signed_x509_certificate* target, asn1struct* source)
{
    parse_huge(target.rsa_signature_value, source);
    return 0;
}

/**
 * An RSA signature is an ASN.1 DER-encoded PKCS-7 structure including
 * the OID of the signature algorithm (again), and the signature value.
 */
private int validate_certificate_rsa(signed_x509_certificate* certificate,
    ref rsa_key public_key)
{
    asn1struct pkcs7_signature;
    asn1struct* hash_value;
    int valid = 0;

    auto pkcs7_signature_decrypted = rsa_decrypt(
            (*(cast(ubyte**) &certificate.rsa_signature_value + 1))[0 .. certificate.rsa_signature_value.length],
            public_key
    );

    if (pkcs7_signature_decrypted is null)
    {
        fprintf(stderr, "Unable to decode signature value.\n");
        return valid;
    }
    if (asn1parse(pkcs7_signature_decrypted.ptr,
                cast(int) pkcs7_signature_decrypted.length,
                &pkcs7_signature))
    {
        fprintf(stderr, "Unable to parse signature\n");
        return valid;
    }

    hash_value = pkcs7_signature.children.next;

    if (memcmp(hash_value.data, certificate.hash, certificate.hash_len))
    {
        valid = 0;
      }
    else
    {
        valid = 1;
    }

    asn1free( &pkcs7_signature );

    return valid;
}

/**
 * This is called by "receive_server_hello" when the "certificate" PDU
 * is encountered.  The input to this function should be a certificate chain.
 * The most important certificate is the first one, since this contains the
 * public key of the subject as well as the DNS name information (which
 * has to be verified against).
 * Each subsequent certificate acts as a signer for the previous certificate.
 * Each signature is verified by this function.
 * The public key of the first certificate in the chain will be returned in
 * "server_public_key" (subsequent certificates are just needed for signature
 * verification).
 * TODO verify signatures.
 */
void parseX509Chain(const(ubyte)* buffer,
                    int pdu_length,
                    public_key_info *server_public_key)
{
    int pos;
    signed_x509_certificate certificate;
    uint chain_length, certificate_length;
    const(ubyte)* ptr = buffer;

    // TODO this won't work on a big-endian machine
    chain_length = (*ptr << 16) | (*(ptr + 1) << 8) | (*(ptr + 2));
    ptr += 3;

    // The chain length is actually redundant since the length of the PDU has
    // already been input.
    assert (chain_length == (pdu_length - 3));

    while ((ptr - buffer) < pdu_length)
    {
        // TODO this won't work on a big-endian machine
        certificate_length = (*ptr << 16) | (*(ptr + 1) << 8) | (*(ptr + 2));
        ptr += 3;

        init_x509_certificate(&certificate);

        parse_x509_certificate(ptr, certificate_length, &certificate);
        if (!pos++)
        {
            server_public_key.algorithm = certificate.tbsCertificate.subjectPublicKeyInfo.algorithm;
            switch (server_public_key.algorithm) with (algorithmIdentifier)
            {
                case rsa:
                    server_public_key.rsa_public_key.modulus =
                            certificate.tbsCertificate.subjectPublicKeyInfo.rsa_public_key.modulus;
                    server_public_key.rsa_public_key.exponent =
                            certificate.tbsCertificate.subjectPublicKeyInfo.rsa_public_key.exponent;
                    break;
                default:
                    break;
            }
        }

        ptr += certificate_length;

        // TODO compute the hash of the certificate so that it can be validated by
        // the next one

        free_x509_certificate(&certificate);
    }
    buffer = ptr;
}

/**
 * Validate that the given ASN.1 node is of the expected tag type and has (at least)
 * the given number of child nodes.  Return true if it passes all checks, false
 * otherwise.
 * This isn't shown in the book.
 */
int validate_node(asn1struct* source,
                  int expected_tag,
                  int expected_children,
                  const(char)* desc)
{
    asn1struct* child;
    int counted_children = 0;

    if (!source)
    {
        fprintf(stderr, "Error - '%s' missing.\n", desc);
        return 0;
    }

    if (source.tag != expected_tag)
    {
        fprintf(stderr, "Error parsing '%s'; expected a %d tag, got a %d.\n",
                desc, expected_tag, source.tag);
        return 0;
    }

    child = source.children;

    while (counted_children < expected_children)
    {
        if (!child)
        {
            fprintf(stderr, "Error parsing '%s'; expected %d children, found %d.\n",
                    desc, expected_children, counted_children);
            return 0;
        }
        counted_children++;
        child = child.next;
    }

    return 1;
}
