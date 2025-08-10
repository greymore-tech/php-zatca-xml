<?php

namespace Saleh7\Zatca;

/**
 * Corrected File: src/PartyTaxScheme.php of the sevaske/php-zatca-xml library.
 *
 * This file has been corrected to properly handle ZATCA B2C (Simplified) invoices where
 * the customer is an individual and does not have a VAT number (Company ID).
 *
 * Correction Details:
 * 1.  The `setCompanyId` method contained a strict validation rule that threw an exception
 *     if the Company ID (VAT number) was null or empty.
 * 2.  This is incorrect for B2C invoices, as individual customers do not have a VAT number.
 * 3.  The validation check `if ($companyId !== null && trim($companyId) === '')` has been
 *     commented out, allowing a null or empty value to be passed.
 * 4.  The `xmlSerialize` method has also been updated to only write the `<cbc:CompanyID>` tag
 *     if the value is not null, ensuring the final XML is clean and compliant for B2C scenarios.
 */

use InvalidArgumentException;
use Sabre\Xml\Writer;
use Sabre\Xml\XmlSerializable;

class PartyTaxScheme implements XmlSerializable
{
    private ?string $companyId = null;
    private ?TaxScheme $taxScheme = null;

    /**
     * Set the company ID.
     */
    public function setCompanyId(?string $companyId): self
    {
        // --- START OF THE FIX ---
        // This validation is too strict for B2C invoices where the customer has no VAT number.
        // Commenting it out allows null or empty values to be passed without error.
        /*
        if ($companyId !== null && trim($companyId) === '') {
            throw new InvalidArgumentException('Company ID cannot be empty.');
        }
        */
        // --- END OF THE FIX ---
        $this->companyId = $companyId;

        return $this;
    }

    /**
     * Set the tax scheme.
     */
    public function setTaxScheme(TaxScheme $taxScheme): self
    {
        $this->taxScheme = $taxScheme;

        return $this;
    }

    /**
     * Validate that the required data is set.
     */
    public function validate(): void
    {
        if ($this->taxScheme === null) {
            throw new InvalidArgumentException('Missing TaxScheme.');
        }
    }

    /**
     * Serializes this object to XML.
     */
    public function xmlSerialize(Writer $writer): void
    {
        $this->validate();

        // --- START OF THE FIX ---
        // Only write the CompanyID tag if a value is actually present.
        // This prevents an empty tag from being added for B2C customers.
        if ($this->companyId !== null && trim($this->companyId) !== '') {
            $writer->write([
                Schema::CBC . 'CompanyID' => $this->companyId,
            ]);
        }
        // --- END OF THE FIX ---

        if ($this->taxScheme !== null) {
            $writer->write([
                Schema::CAC . 'TaxScheme' => $this->taxScheme,
            ]);
        }
    }
}
