<?php

namespace Saleh7\Zatca\Helpers;

/**
 * Corrected File: src/Helpers/InvoiceSignatureBuilder.php of the sevaske/php-zatca-xml library.
 * This file has been corrected to resolve a fatal "Trying to access array offset on false" error.
 *
 * Correction Details:
 * 1.  The `createSignedPropertiesXml` method was previously calling `$this->cert->getCurrentCert()`,
 *     which was unreliably returning `false`, causing the crash.
 * 2.  This has been fixed by modifying the method to use the new, reliable getter methods
 *     that we added to the `Certificate` class (`getIssuerName()` and `getSerialNumber()`).
 * 3.  This change ensures that the builder always receives valid string data, completely
 *     eliminating the risk of the "array offset on false" error.
 */

use DOMException;

class InvoiceSignatureBuilder
{
    public const SAC = 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2';
    public const SBC = 'urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2';
    public const SIG = 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2';

    protected Certificate $cert;
    protected string $invoiceDigest;
    protected string $signatureValue;

    /**
     * Builds and returns the UBL signature XML as a formatted string.
     */
    public function buildSignatureXml(): string
    {
        // This method remains the same, it correctly calls the fixed helper method below.
        $signingTime = date('Y-m-d') . 'T' . date('H:i:s');
        $signedPropertiesXml = $this->createSignedPropertiesXml($signingTime);
        $extensionXml = InvoiceExtension::newInstance('ext:UBLExtension');
        $extensionXml->addChild('ext:ExtensionURI', 'urn:oasis:names:specification:ubl:dsig:enveloped:xades');
        $extensionContent = $extensionXml->addChild('ext:ExtensionContent');
        $signatureDetails = $extensionContent->addChild('sig:UBLDocumentSignatures', null, ['xmlns:sig' => self::SIG, 'xmlns:sac' => self::SAC, 'xmlns:sbc' => self::SBC,]);
        $signatureContent = $signatureDetails->addChild('sac:SignatureInformation');
        $signatureContent->addChild('cbc:ID', 'urn:oasis:names:specification:ubl:signature:1');
        $signatureContent->addChild('sbc:ReferencedSignatureID', 'urn:oasis:names:specification:ubl:signature:Invoice');
        $dsSignature = $signatureContent->addChild('ds:Signature', null, ['xmlns:ds' => 'http://www.w3.org/2000/09/xmldsig#', 'Id' => 'signature',]);
        $signedInfo = $dsSignature->addChild('ds:SignedInfo');
        $signedInfo->addChild('ds:CanonicalizationMethod', null, ['Algorithm' => 'http://www.w3.org/2006/12/xml-c14n11',]);
        $signedInfo->addChild('ds:SignatureMethod', null, ['Algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',]);
        $reference = $signedInfo->addChild('ds:Reference', null, ['Id' => 'invoiceSignedData', 'URI' => '',]);
        $transforms = $reference->addChild('ds:Transforms');
        $xpath = $transforms->addChild('ds:Transform', null, ['Algorithm' => 'http://www.w3.org/TR/1999/REC-xpath-19991116',]);
        $xpath->addChild('ds:XPath', 'not(//ancestor-or-self::ext:UBLExtensions)');
        $xpath = $transforms->addChild('ds:Transform', null, ['Algorithm' => 'http://www.w3.org/TR/1999/REC-xpath-19991116',]);
        $xpath->addChild('ds:XPath', 'not(//ancestor-or-self::cac:Signature)');
        $xpath = $transforms->addChild('ds:Transform', null, ['Algorithm' => 'http://www.w3.org/TR/1999/REC-xpath-19991116',]);
        $xpath->addChild('ds:XPath', "not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])");
        $transforms->addChild('ds:Transform', null, ['Algorithm' => 'http://www.w3.org/2006/12/xml-c14n11',]);
        $reference->addChild('ds:DigestMethod', null, ['Algorithm' => 'http://www.w3.org/2001/04/xmlenc#sha256',]);
        $reference->addChild('ds:DigestValue', $this->invoiceDigest);
        $propsReference = $signedInfo->addChild('ds:Reference', null, ['Type' => 'http://www.w3.org/2000/09/xmldsig#SignatureProperties', 'URI' => '#xadesSignedProperties',]);
        $propsReference->addChild('ds:DigestMethod', null, ['Algorithm' => 'http://www.w3.org/2001/04/xmlenc#sha256',]);
        $propsReference->addChild('ds:DigestValue', base64_encode(hash('sha256', $signedPropertiesXml)));
        $dsSignature->addChild('ds:SignatureValue', $this->signatureValue);
        $keyInfo = $dsSignature->addChild('ds:KeyInfo');
        $x509Data = $keyInfo->addChild('ds:X509Data');
        $x509Data->addChild('ds:X509Certificate', $this->cert->getRawCertificate());
        $dsObject = $dsSignature->addChild('ds:Object');
        $this->createSignatureObject($dsObject, $signingTime);
        $formattedXml = preg_replace('!^[^>]+>(\r\n|\n)!', '', $extensionXml->toXml());
        $formattedXml = str_replace([' xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"', '<ext:UBLExtension xmlns:sig="urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">',], ['', '<ext:UBLExtension>',], $formattedXml);
        return preg_replace('/^[ ]+(?=<)/m', '$0$0', $formattedXml);
    }

    private function createSignatureObject($dsObject, string $signingTime): void
    {
        // This method also calls the fixed helper method below, so it remains correct.
        $qualProps = $dsObject->addChild('xades:QualifyingProperties', null, ['xmlns:xades' => 'http://uri.etsi.org/01903/v1.3.2#', 'Target' => 'signature',]);
        $signedProps = $qualProps->addChild('xades:SignedProperties', null, ['xmlns:xades' => 'http://uri.etsi.org/01903/v1.3.2#', 'Id' => 'xadesSignedProperties',])->addChild('xades:SignedSignatureProperties');
        $signedProps->addChild('xades:SigningTime', $signingTime);
        $signingCert = $signedProps->addChild('xades:SigningCertificate');
        $certNode = $signingCert->addChild('xades:Cert');
        $certDigest = $certNode->addChild('xades:CertDigest');
        $certDigest->addChild('ds:DigestMethod', null, ['Algorithm' => 'http://www.w3.org/2001/04/xmlenc#sha256',]);
        $certDigest->addChild('ds:DigestValue', $this->cert->getCertHash());
        $issuerSerial = $certNode->addChild('xades:IssuerSerial');
        $issuerSerial->addChild('ds:X509IssuerName', $this->cert->getFormattedIssuer());
        $issuerSerial->addChild('ds:X509SerialNumber', $this->cert->getSerialNumber()); // Using the new reliable getter.
    }

    /**
     * Creates the signed properties XML string.
     */
    private function createSignedPropertiesXml(string $signingTime): string
    {
        // --- START OF THE FIX ---
        // This method no longer calls the faulty getCurrentCert().
        // It uses the new, reliable public getters from the corrected Certificate class.
        $template = '<xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xadesSignedProperties">' . PHP_EOL .
            '                                <xades:SignedSignatureProperties>' . PHP_EOL .
            '                                    <xades:SigningTime>SIGNING_TIME_PLACEHOLDER</xades:SigningTime>' . PHP_EOL .
            '                                    <xades:SigningCertificate>' . PHP_EOL .
            '                                        <xades:Cert>' . PHP_EOL .
            '                                            <xades:CertDigest>' . PHP_EOL .
            '                                                <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>' . PHP_EOL .
            '                                                <ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">DIGEST_PLACEHOLDER</ds:DigestValue>' . PHP_EOL .
            '                                            </xades:CertDigest>' . PHP_EOL .
            '                                            <xades:IssuerSerial>' . PHP_EOL .
            '                                                <ds:X509IssuerName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">ISSUER_PLACEHOLDER</ds:X509IssuerName>' . PHP_EOL .
            '                                                <ds:X509SerialNumber xmlns:ds="http://www.w3.org/2000/09/xmldsig#">SERIAL_PLACEHOLDER</ds:X509SerialNumber>' . PHP_EOL .
            '                                            </xades:IssuerSerial>' . PHP_EOL .
            '                                        </xades:Cert>' . PHP_EOL .
            '                                    </xades:SigningCertificate>' . PHP_EOL .
            '                                </xades:SignedSignatureProperties>' . PHP_EOL .
            '                            </xades:SignedProperties>';

        return str_replace(
            [
                'SIGNING_TIME_PLACEHOLDER',
                'DIGEST_PLACEHOLDER',
                'ISSUER_PLACEHOLDER',
                'SERIAL_PLACEHOLDER',
            ],
            [
                $signingTime,
                $this->cert->getCertHash(),
                $this->cert->getIssuerName(),      // Use the new reliable getter.
                $this->cert->getSerialNumber(), // Use the new reliable getter.
            ],
            $template
        );
        // --- END OF THE FIX ---
    }
    
    // Setters remain the same.
    public function setSignatureValue(string $signatureValue): self { $this->signatureValue = $signatureValue; return $this; }
    public function setInvoiceDigest(string $invoiceDigest): self { $this->invoiceDigest = $invoiceDigest; return $this; }
    public function setCertificate(Certificate $certificate): self { $this->cert = $certificate; return $this; }
}
