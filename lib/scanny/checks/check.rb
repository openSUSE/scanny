require 'scanny/issue'

module Scanny
  module Checks
    class Check
      attr_accessor :file, :line

      def initialize
        @issues = []
      end

     def position(offset = 0)
        "#{@line[2]}:#{@line[1] + offset}"
      end

      def evaluate_node(node)
      end

      def add_issue(impact, message, filename = @file, line = @line)
        @issues ||= []
        @issues << Scanny::Issue.new("#{filename}", "#{line}", impact, message)
      end

      def issues
        @issues
      end
    end
  end
end
