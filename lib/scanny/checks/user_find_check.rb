module Scanny
  module Checks
    class UserFindCheck < Check
      def pattern
        pattern_user_find
      end

      def check(node)
        issue :medium, warning_message, :cwe => [89, 592]
      end

      private

      def warning_message
        "Create a user object using the " +
        "parameters can cause security problems"
      end

      # User.find(:first, :conditions => params[:input])
      def pattern_user_find
      <<-EOT
        SendWithArguments<
          arguments = ActualArguments<
            array = [
              any*,
              SendWithArguments<
                name = :[],
                receiver = Send<name = :params>
              >,
              any*
            ]
          >,
          name = :find,
          receiver = ConstantAccess<name = :User>
        >
      EOT
      end
    end
  end
end