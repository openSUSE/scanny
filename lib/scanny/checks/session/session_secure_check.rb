module Scanny
  module Checks
    module Session
      class SessionSecureCheck < Check
        def pattern
          pattern_session_settings
        end

        def check(node)
          issue :info, warning_message, :cwe => 614
        end

        private

        def warning_message
          "Bad session security setting can cause problems"
        end

        # ActionController::Base.session_options[:session_secure]
        def pattern_session_settings
          <<-EOT
            ElementAssignment<
              arguments = ActualArguments<
                array = [
                  SymbolLiteral<value = :session_secure | :secure>,
                  any
                ]
              >,
              name = :[]=,
              receiver = Send<
                name = :session_options,
                receiver = ScopedConstant<
                  name = :Base,
                  parent = ConstantAccess<name = :ActionController>
                >
              >
            >
          EOT
        end
      end
    end
  end
end