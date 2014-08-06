# Usage:
# bundle exec ruby test/sign_document.rb <path_to_saml_response_to_sign>

require 'rubygems'
require "rexml/document"
require "rexml/xpath"
require "openssl"
require 'nokogiri'
require "digest/sha1"
require "digest/sha2"
require "onelogin/ruby-saml/validation_error"
require "base64"

module XMLSecurity

  class SignDocument < REXML::Document
    C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
    DSIG = "http://www.w3.org/2000/09/xmldsig#"

    attr_accessor :signed_element_id
    attr_reader :signed_document

    def initialize(response)
      super(response)
      extract_signed_element_id

      cert_element = REXML::XPath.first(self, "//ds:X509Certificate", { "ds"=>DSIG })
      raise OneLogin::RubySaml::ValidationError.new("Certificate element missing in response (ds:X509Certificate)") unless cert_element
      base64_cert  = cert_element.text

      soft = true
      # validate references

      # check for inclusive namespaces
      inclusive_namespaces = extract_inclusive_namespaces

      document = Nokogiri.parse(self.to_s)

      @signed_document = REXML::Document.new(self.to_s).root

      # create a working copy so we don't modify the original
      @working_copy ||= REXML::Document.new(self.to_s).root

      # store and remove signature node
      @sig_element ||= begin
        element = REXML::XPath.first(@working_copy, "//ds:Signature", {"ds"=>DSIG})
        element.remove
      end

      # verify signature
      signed_info_element     = REXML::XPath.first(@sig_element, "//ds:SignedInfo", {"ds"=>DSIG})
      noko_sig_element = document.at_xpath('//ds:Signature', 'ds' => DSIG)
      noko_signed_info_element = noko_sig_element.at_xpath('./ds:SignedInfo', 'ds' => DSIG)
      canon_algorithm = canon_algorithm REXML::XPath.first(@sig_element, '//ds:CanonicalizationMethod', 'ds' => DSIG)
      canon_string = noko_signed_info_element.canonicalize(canon_algorithm)
      noko_sig_element.remove

      # check digests
      REXML::XPath.each(@sig_element, "//ds:Reference", {"ds"=>DSIG}) do |ref|
        uri                           = ref.attributes.get_attribute("URI").value

        hashed_element                = document.at_xpath("//*[@ID='#{uri[1..-1]}']")
        canon_algorithm               = canon_algorithm REXML::XPath.first(ref, '//ds:CanonicalizationMethod', 'ds' => DSIG)
        canon_hashed_element          = hashed_element.canonicalize(canon_algorithm, inclusive_namespaces)

        digest_algorithm              = algorithm(REXML::XPath.first(ref, "//ds:DigestMethod", 'ds' => DSIG))

        hash                          = digest_algorithm.digest(canon_hashed_element)
        digest_value                  = Base64.decode64(REXML::XPath.first(ref, "//ds:DigestValue", {"ds"=>DSIG}).text)

        # puts "Digest value should be: #{Base64.encode64(hash).split.join}"
        REXML::XPath.first(@signed_document, '//ds:DigestValue', {"ds"=>DSIG}).text = Base64.encode64(hash).split.join
      end

      base64_signature        = REXML::XPath.first(@sig_element, "//ds:SignatureValue", {"ds"=>DSIG}).text
      signature               = Base64.decode64(base64_signature)

      # signature method
      signature_algorithm     = algorithm(REXML::XPath.first(signed_info_element, "//ds:SignatureMethod", {"ds"=>DSIG}))

      root_key = OpenSSL::PKey::RSA.new 2048 # the CA's public/private key
      root_ca = OpenSSL::X509::Certificate.new
      root_ca.version = 2 # cf. RFC 5280 - to make it a "v3" certificate
      root_ca.serial = 1
      root_ca.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-lang/CN=Ruby CA"
      root_ca.issuer = root_ca.subject # root CA's are "self-signed"
      root_ca.public_key = root_key.public_key
      root_ca.not_before = Time.now
      root_ca.not_after = root_ca.not_before + 2 * 365 * 24 * 60 * 60 # 2 years validity
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = root_ca
      ef.issuer_certificate = root_ca
      root_ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
      root_ca.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
      root_ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
      root_ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
      root_ca.sign(root_key, OpenSSL::Digest::SHA256.new)

      key = OpenSSL::PKey::RSA.new 2048
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 2
      cert.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-lang/CN=Ruby certificate"
      cert.issuer = root_ca.subject # root CA is the issuer
      cert.public_key = key.public_key
      cert.not_before = Time.now
      cert.not_after = cert.not_before + 1 * 365 * 24 * 60 * 60 # 1 years validity
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      ef.issuer_certificate = root_ca
      cert.add_extension(ef.create_extension("keyUsage","digitalSignature", true))
      cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
      cert.sign(root_key, OpenSSL::Digest::SHA256.new)

      cert_text = cert.to_pem
      base64_cert = Base64.encode64(cert_text).split().join
      REXML::XPath.first(@signed_document, "//ds:X509Certificate", { "ds"=>DSIG }).text = base64_cert

      cert_text               = Base64.decode64(base64_cert)
      cert                    = OpenSSL::X509::Certificate.new(cert_text)

      signature = key.sign(signature_algorithm.new, canon_string)
      base64_signature = Base64.encode64(signature).split.join
      REXML::XPath.first(@signed_document, "//ds:SignatureValue", {"ds"=>DSIG}).text = base64_signature

      raise "failed to generate" unless cert.public_key.verify(signature_algorithm.new, signature, canon_string).to_s

      # puts "Cert should be: #{base64_cert}"
      # puts "Signature should be: #{base64_signature}"
    end

    private

    def digests_match?(hash, digest_value)
      hash == digest_value
    end

    def extract_signed_element_id
      reference_element       = REXML::XPath.first(self, "//ds:Signature/ds:SignedInfo/ds:Reference", {"ds"=>DSIG})
      self.signed_element_id  = reference_element.attribute("URI").value[1..-1] unless reference_element.nil?
    end

    def canon_algorithm(element)
      algorithm = element.attribute('Algorithm').value if element
      case algorithm
        when "http://www.w3.org/2001/10/xml-exc-c14n#"         then Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
        when "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" then Nokogiri::XML::XML_C14N_1_0
        when "http://www.w3.org/2006/12/xml-c14n11"            then Nokogiri::XML::XML_C14N_1_1
        else                                                        Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
      end
    end

    def algorithm(element)
      algorithm = element.attribute("Algorithm").value if element
      algorithm = algorithm && algorithm =~ /sha(.*?)$/i && $1.to_i
      case algorithm
      when 256 then OpenSSL::Digest::SHA256
      when 384 then OpenSSL::Digest::SHA384
      when 512 then OpenSSL::Digest::SHA512
      else
        OpenSSL::Digest::SHA1
      end
    end

    def extract_inclusive_namespaces
      if element = REXML::XPath.first(self, "//ec:InclusiveNamespaces", { "ec" => C14N })
        prefix_list = element.attributes.get_attribute("PrefixList").value
        prefix_list.split(" ")
      else
        []
      end
    end

  end
end

puts XMLSecurity::SignDocument.new(File.read(ARGV.first)).signed_document


