module Scanny
  module Checks
    module Helpers
      module System
        def build_pattern_exec_command(method)
        <<-EOT
          SendWithArguments
          <
            name = :system | :exec,
            arguments = ActualArguments<
              array = [
                any*,
                StringLiteral<string *= /#{method}/>,
                any*
              ]
            >
          >
          |
          ExecuteString<string *= /#{method}/>
        EOT
        end
      end
    end
  end
end
