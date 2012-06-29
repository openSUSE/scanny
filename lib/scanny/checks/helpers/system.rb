module Scanny
  module Checks
    module Helpers
      module System
        def build_pattern_exec_command(command)
          command = command.inspect.slice(1...-1) if command.is_a?(Regexp)

          <<-EOT
            SendWithArguments
            <
              name = :system | :exec,
              arguments = ActualArguments<
                array = [
                  any*,
                  StringLiteral<string *= /#{command}/>,
                  any*
                ]
              >
            >
            |
            ExecuteString<string *= /#{command}/>
          EOT
        end
      end
    end
  end
end
