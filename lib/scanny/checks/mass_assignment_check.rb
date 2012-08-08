module Scanny
  module Checks
    class MassAssignmentCheck < Check
      def pattern
        pattern_create_object_from_params
      end

      def check(node)
        issue :high, warning_message, :cwe => 642
      end

      private

      def warning_message
        "Create objects without defense against mass assignment" +
        "can cause dangerous errors in the database"
      end

      # User.new(params[:user])
      def pattern_create_object_from_params
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                SendWithArguments<
                  name = :[],
                  receiver = Send<name = :params>
                >
                |
                HashLiteral<
                array = [
                  any{odd},
                  SendWithArguments<
                    name = :[],
                    receiver = Send<name = :params>
                  >,
                  any{even}
                ]
                >
              ]
            >,
            name = :new | :create | :update_attributes
          >
        EOT
      end
    end
  end
end