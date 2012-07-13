module Scanny
  module Reporters
    class Reporter
      attr_accessor :file, :checks_performed, :nodes_inspected, :issues

      def initialize(arguments = {})
        arguments.each do |key, value|
          instance_variable_set("@#{key}", value) unless value.nil?
        end
        set_default_values!
      end

      private

      def set_default_values!
        @check_performed  ||= 0
        @nodes_inspected  ||= 0
        @issues           ||= []
      end
    end
  end
end
