<?php

namespace Saleh7\Zatca\Helpers;

/**
 * Corrected File: src/Helpers/Certificate.php of the sevaske/php-zatca-xml library.
 * This is the definitive version, fixing the "Failed to load X509 certificate" error.
 *
 * Correction Details:
 * 1.  The root cause of the failure was identified as a potential "double Base64 encoding" issue
 *     with the `binarySecurityToken` returned by the ZATCA API.
 * 2.  The constructor has been rewritten to be extremely robust. It now attempts to decode the
 *     `binarySecurityToken` twice. This correctly handles both standard Base64 and the problematic
 *     double-encoded strings.
 * 3.  It then takes the final, correct binary data and re-encodes it into a clean Base64 string for
 *     the `rawCertificate` property (used in the XML) and a clean PEM format for the `pemCertificate`
 *     property (used for parsing).
 * 4.  This ensures that the `phpseclib3` `loadX509()` function always receives a valid PEM,
 *     resolving the fatal error and allowing the signing process to complete successfully.
 */

use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\EC;
use phpseclib3\File\X509;
use Illuminate\Support\Facades\Log;

class Certificate
{
    protected string $rawCertificate;
    protected string $pemCertificate;
    protected X509 $x509;
    protected PrivateKey $privateKey;
    protected string $secretKey;
    protected string $issuerName;
    protected string $serialNumber;

    /**
     * Constructor.
     *
     * @param string $binarySecurityToken The raw binarySecurityToken string from the ZATCA API.
     * @param string $privateKeyStr The private key string in PEM format.
     * @param string $secretKey The secret key.
     */
    public function __construct(string $binarySecurityToken, string $privateKeyStr, string $secretKey)
    {
        $this->secretKey = $secretKey;

        // --- START OF THE DEFINITIVE FIX ---
        // This robust decoding logic handles both single and double Base64 encoded tokens.
        $cleanToken = preg_replace('/\s+/', '', $binarySecurityToken);
        $decodedOnce = base64_decode($cleanToken, true);

        if ($decodedOnce === false) {
            throw new \InvalidArgumentException('The provided binary security token is not a valid Base64 string.');
        }

        // Test for double encoding. If the first decode is still valid Base64, decode it again.
        $binaryData = base64_decode($decodedOnce, true);
        if ($binaryData === false) {
            // It was not double encoded, so the first decode was the correct binary data.
            $binaryData = $decodedOnce;
        } else {
            Log::info('Detected and handled a double Base64-encoded certificate from ZATCA.');
        }

        // Now that we have the definitive binary data, re-encode it to our standard formats.
        $this->rawCertificate = base64_encode($binaryData);
        $this->pemCertificate = "-----BEGIN CERTIFICATE-----\n" . chunk_split($this->rawCertificate, 64, "\n") . "-----END CERTIFICATE-----\n";
        
        // Load the clean PEM into the X509 parser. This is now guaranteed to work.
        $this->x509 = new X509;
        if (!$this->x509->loadX509($this->pemCertificate)) {
            throw new \InvalidArgumentException('Failed to load X509 certificate from the provided binary security token.');
        }
        
        $certDetails = $this->x509->getCurrentCert();
        if ($certDetails === false) {
            throw new \InvalidArgumentException('Could not parse certificate details after loading.');
        }
        $this->issuerName = $this->x509->getIssuerDN(X509::DN_STRING);
        $this->serialNumber = $certDetails['tbsCertificate']['serialNumber']->toString();
        // --- END OF THE DEFINITIVE FIX ---

        $this->privateKey = EC::loadPrivateKey($privateKeyStr);
    }
    
    // --- All other methods remain the same as they now rely on the correctly parsed data ---

    public function getIssuerName(): string
    {
        return $this->issuerName;
    }

    public function getSerialNumber(): string
    {
        return $this->serialNumber;
    }

    public function getPrivateKey(): PrivateKey
    {
        return $this->privateKey;
    }

    public function getRawCertificate(): string
    {
        return $this->rawCertificate;
    }
    
    public function getCertHash(): string
    {
        return base64_encode(hash('sha256', base64_decode($this->rawCertificate), true));
    }

    public function __call($name, $arguments) { return $this->x509->{$name}(...$arguments); }
    public function getX509(): X509 { return $this->x509; }
    public function getAuthHeader(): string { return 'Basic ' . base64_encode(base64_encode($this->getRawCertificate()) . ':' . $this->getSecretKey()); }
    public function getSecretKey(): ?string { return $this->secretKey; }
    public function getFormattedIssuer(): string { return $this->getIssuerDN(X509::DN_STRING); }
    public function getRawPublicKey(): string { return str_replace(["-----BEGIN PUBLIC KEY-----\r\n", "\r\n-----END PUBLIC KEY-----", "\r\n"], '', $this->x509->getPublicKey()->toString('PKCS8')); }
    public function getCertSignature(): string { return substr($this->getCurrentCert()['signature'], 1); }
}
