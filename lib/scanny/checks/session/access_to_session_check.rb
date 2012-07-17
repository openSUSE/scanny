module Scanny
  module Checks
    module Session
      class AccessToSessionCheck < Check
        def pattern
          [
              pattern_session_access,
              pattern_session_assignment
          ].join("|")
        end

        def check(node)
          issue :info, warning_message, :cwe => 0
        end

        private

        def warning_message
          "Referring to a session in the wrong way" +
          "can lead to errors that reduce security level"
        end

        # session[:password]
        def pattern_session_access
          <<-EOT
          SendWithArguments<
            name = :[],
            receiver = Send<name = :session | :cookie>
          >
          EOT
        end

        # session[:admin] = true
        def pattern_session_assignment
          <<-EOT
          ElementAssignment<
            name = :[]=,
            receiver = Send<name = :session | :cookie>
          >
          EOT
        end
      end
    end
  end
end