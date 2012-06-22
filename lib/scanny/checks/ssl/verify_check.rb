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
          "Disable certificate verification can" +
          "lead to connect to an unauthorized server"
        end

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

        def pattern_ca_file
          <<-EOT
          LocalVariableAssignment | InstanceVariableAssignment
          <
            name = :ca_file | :ca_path | :@ca_file | :@ca_path,
            value = NilLiteral
          >
          EOT
        end
      end
    end
  end
end