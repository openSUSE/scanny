module Scanny
  module Checks
    module SSL
      class VerifyCheck < Check
        def pattern
          [
            pattern_ssl_verify_none,
            pattern_ca_file
          ].join("|")
        end

        def check(node)
          issue :high, warning_message, :cwe => [296, 297, 298, 299, 300, 599]
        end

        private

        def warning_message
          "Disable certificate verification can " +
          "lead to connect to an unauthorized server"
        end

        # OpenSSL::SSL::VERIFY_NONE
        def pattern_ssl_verify_none
          <<-EOT
          ScopedConstant<
            name = :VERIFY_NONE,
            parent = ScopedConstant<
              name = :SSL,
              parent = ConstantAccess<name = :OpenSSL>
            >
          >
          EOT
        end


        # ssl_context.ca_file = nil
        def pattern_ca_file
          <<-EOT
          AttributeAssignment<
            arguments = ActualArguments<
              array = [
                NilLiteral
              ]
            >,
            name = :ca_path= | :ca_file=
          >
          EOT
        end
      end
    end
  end
end