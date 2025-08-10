<?php

namespace Saleh7\Zatca\Helpers;

/**
 * Corrected File: src/Helpers/Certificate.php of the sevaske/php-zatca-xml library.
 *
 * This file has been corrected to resolve a fatal "Trying to access array offset on false" error
 * that occurs during the signing process for B2C invoices.
 *
 * Correction Details:
 * 1.  The original constructor was not robust enough to handle different certificate formats
 *     (raw Base64 vs. PEM) consistently for all its methods.
 * 2.  The `__construct` method now immediately decodes the incoming certificate string and
 *     re-formats it into a standard PEM format. This PEM string is stored internally and used
 *     for all subsequent operations, like parsing with `phpseclib3`.
 * 3.  The `getRawCertificate()` method has been updated to return the raw, uninterrupted Base64
 *     string (without PEM headers/footers), which is what ZATCA requires in the final XML.
 * 4.  This ensures that when `InvoiceSignatureBuilder` calls `getCurrentCert()`, it receives a
 *     valid parsed array, not `false`, thus fixing the fatal error.
 */

use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\EC;
use phpseclib3\File\X509;

class Certificate
{
    /**
     * The raw, uninterrupted Base64 certificate content.
     */
    protected string $rawCertificate;

    /**
     * The certificate in standard PEM format for reliable parsing.
     */
    protected string $pemCertificate;

    /**
     * The X509 certificate object from phpseclib3.
     */
    protected X509 $x509;

    /**
     * The private key for this certificate.
     */
    protected PrivateKey $privateKey;

    /**
     * The secret key used for authentication.
     */
    protected string $secretKey;

    /**
     * Constructor.
     *
     * @param string $rawCert The raw certificate string (binarySecurityToken).
     * @param string $privateKeyStr The private key string in PEM format.
     * @param string $secretKey The secret key.
     */
    public function __construct(string $rawCert, string $privateKeyStr, string $secretKey)
    {
        $this->secretKey = $secretKey;

        // --- START OF THE FIX ---
        // Store the raw, uninterrupted Base64 string for use in the final XML.
        $this->rawCertificate = preg_replace('/\s+/', '', $rawCert);

        // Create a clean PEM version for reliable parsing with phpseclib3.
        $pemBody = chunk_split($this->rawCertificate, 64, "\n");
        $this->pemCertificate = "-----BEGIN CERTIFICATE-----\n" . $pemBody . "-----END CERTIFICATE-----\n";

        // Load the clean PEM into the X509 parser.
        $this->x509 = new X509;
        if (!$this->x509->loadX509($this->pemCertificate)) {
            throw new \InvalidArgumentException('Failed to load X509 certificate from the provided binary security token.');
        }
        // --- END OF THE FIX ---

        $this->privateKey = EC::loadPrivateKey($privateKeyStr);
    }

    /**
     * Delegate method calls to the underlying X509 object.
     */
    public function __call($name, $arguments)
    {
        return $this->x509->{$name}(...$arguments);
    }

    /**
     * Get the private key.
     */
    public function getPrivateKey(): PrivateKey
    {
        return $this->privateKey;
    }

    /**
     * Get the raw, uninterrupted Base64 certificate content.
     * This is required for the <ds:X509Certificate> tag.
     */
    public function getRawCertificate(): string
    {
        return $this->rawCertificate;
    }

    /**
     * Get the X509 certificate object.
     */
    public function getX509(): X509
    {
        return $this->x509;
    }

    /**
     * Create the authorization header.
     */
    public function getAuthHeader(): string
    {
        return 'Basic ' . base64_encode(base64_encode($this->getRawCertificate()) . ':' . $this->getSecretKey());
    }

    /**
     * Get the secret key.
     */
    public function getSecretKey(): ?string
    {
        return $this->secretKey;
    }

    /**
     * Generate a hash of the certificate.
     */
    public function getCertHash(): string
    {
        // Hash the raw binary data of the certificate.
        return base64_encode(hash('sha256', base64_decode($this->rawCertificate), true));
    }

    /**
     * Get the formatted issuer details.
     */
    public function getFormattedIssuer(): string
    {
        // This method relies on the correctly loaded $this->x509 object.
        return $this->x509->getIssuerDN(X509::DN_STRING);
    }

    /**
     * Get the raw public key in base64 format.
     */
    public function getRawPublicKey(): string
    {
        return str_replace(
            ["-----BEGIN PUBLIC KEY-----\r\n", "\r\n-----END PUBLIC KEY-----", "\r\n"],
            '',
            $this->x509->getPublicKey()->toString('PKCS8')
        );
    }

    /**
     * Get the certificate signature.
     */
    public function getCertSignature(): string
    {
        // This method relies on the correctly loaded $this->x509 object.
        return substr($this->getCurrentCert()['signature'], 1);
    }
}
