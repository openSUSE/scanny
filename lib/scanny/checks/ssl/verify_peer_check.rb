module Scanny
  module Checks
    module SSL
      class VerifyPeerCheck < Check
        def pattern
          pattern_ssl_verify_peer
        end

        def check(node)
          issue :info, warning_message
        end

        private

        def warning_message
          "Change the value of of VERIFY_PEER" +
          "can lead to faulty accepted certificate"
        end

        # OpenSSL::SSL::VERIFY_PEER
        def pattern_ssl_verify_peer
          <<-EOT
          ConstantAssignment<
            constant = ScopedConstant<
              name = :VERIFY_PEER,
              parent = ScopedConstant<
                name = :SSL,
                parent = ConstantAccess<name = :OpenSSL>
              >
            >
          >
          EOT
        end
      end
    end
  end
end