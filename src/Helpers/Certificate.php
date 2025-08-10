<?php

namespace Saleh7\Zatca\Helpers;

/**
 * Corrected File: src/Helpers/Certificate.php of the sevaske/php-zatca-xml library.
 * This version is corrected to be more robust and to expose necessary certificate details.
 *
 * Correction Details:
 * 1.  The constructor now parses the certificate and stores the issuer and serial number
 *     as properties, preventing repeated, potentially failing parsing attempts.
 * 2.  New public getter methods (`getIssuerName()` and `getSerialNumber()`) have been added
 *     so that the `InvoiceSignatureBuilder` can access these values directly and reliably.
 * 3.  This change prevents the "Trying to access array offset on false" error by ensuring
 *     that certificate details are parsed only once and are always available.
 */

use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\EC;
use phpseclib3\File\X509;

class Certificate
{
    protected string $rawCertificate;
    protected string $pemCertificate;
    protected X509 $x509;
    protected PrivateKey $privateKey;
    protected string $secretKey;

    // --- START OF NEW PROPERTIES ---
    protected string $issuerName;
    protected string $serialNumber;
    // --- END OF NEW PROPERTIES ---

    public function __construct(string $rawCert, string $privateKeyStr, string $secretKey)
    {
        $this->secretKey = $secretKey;
        $this->rawCertificate = preg_replace('/\s+/', '', $rawCert);

        $pemBody = chunk_split($this->rawCertificate, 64, "\n");
        $this->pemCertificate = "-----BEGIN CERTIFICATE-----\n" . $pemBody . "-----END CERTIFICATE-----\n";

        $this->x509 = new X509;
        if (!$this->x509->loadX509($this->pemCertificate)) {
            throw new \InvalidArgumentException('Failed to load X509 certificate from the provided binary security token.');
        }

        // --- START OF FIX ---
        // Parse the details once during construction and store them.
        $certDetails = $this->x509->getCurrentCert();
        if ($certDetails === false) {
            throw new \InvalidArgumentException('Could not parse certificate details.');
        }
        $this->issuerName = $this->x509->getIssuerDN(X509::DN_STRING);
        $this->serialNumber = $certDetails['tbsCertificate']['serialNumber']->toString();
        // --- END OF FIX ---

        $this->privateKey = EC::loadPrivateKey($privateKeyStr);
    }
    
    // --- START OF NEW GETTER METHODS ---
    public function getIssuerName(): string
    {
        return $this->issuerName;
    }

    public function getSerialNumber(): string
    {
        return $this->serialNumber;
    }
    // --- END OF NEW GETTER METHODS ---

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

    // All other methods from the library can remain as they are.
    // The following are included for completeness.
    public function __call($name, $arguments) { return $this->x509->{$name}(...$arguments); }
    public function getX509(): X509 { return $this->x509; }
    public function getAuthHeader(): string { return 'Basic ' . base64_encode(base64_encode($this->getRawCertificate()) . ':' . $this->getSecretKey()); }
    public function getSecretKey(): ?string { return $this->secretKey; }
    public function getFormattedIssuer(): string { return $this->getIssuerDN(X509::DN_STRING); }
    public function getRawPublicKey(): string { return str_replace(["-----BEGIN PUBLIC KEY-----\r\n", "\r\n-----END PUBLIC KEY-----", "\r\n"], '', $this->x509->getPublicKey()->toString('PKCS8')); }
    public function getCertSignature(): string { return substr($this->getCurrentCert()['signature'], 1); }
}
