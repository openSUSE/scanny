module Scanny
  module Checks
    module Helpers
      # system("command")
      # `command`
      def build_pattern_exec_command(command)
        command = command.to_s if command.is_a?(Symbol)
        result  = command.inspect

        <<-EOT
            SendWithArguments
            <
              name = :system | :exec | :spawn,
              arguments = ActualArguments<
                array = [
                  any*,
                  StringLiteral<string *= #{result}>,
                  any*
                ]
              >
            >
            |
            ExecuteString<string *= #{result}>
        EOT
      end
    end
  end
end