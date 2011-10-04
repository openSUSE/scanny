module Scanny
  module Checks
    # Checks for use of "params[:id]" in parameters of certain methods that
    # requires authorizaton checks.
    class AccessControlCheck < Check
      def pattern
        <<-EOT
          SendWithArguments<
            name      = :new | :create,
            arguments = ActualArguments<
              array = [
                HashLiteral<
                  array = [
                    any{odd},
                    SendWithArguments<
                      receiver  = Send<name = :params>,
                      name      = :[],
                      arguments = ActualArguments<array = [SymbolLiteral<value = :id>]>
                    >,
                    any{even}
                  ]
                >
              ]
            >
          >
          |
          SendWithArguments<
            name      = :delete | :destroy,
            arguments = ActualArguments<
              array = [
                any*,
                SendWithArguments<
                  receiver  = Send<name = :params>,
                  name      = :[],
                  arguments = ActualArguments<array = [SymbolLiteral<value = :id>]>
                >,
                any*
              ]
            >
          >
        EOT
      end

      def check(node)
        issue :medium,
          "Using \"params[:id]\" requires proper authorization check.",
          :cwe => 285
      end
    end
  end
end
