require "yaml"
require "machete"

module Scanny
  class Runner
    attr_reader :checks

    def initialize(*checks)
      if checks.empty?
        @checks = check_classes
      else
        @checks = checks
      end
    end

    def check(file, input)
      report        = Report.new(file)
      ast           = input.to_ast
      ignored_lines = extract_ignored_lines(input)

      @checks.each do |check|
        nodes_to_inspect = Machete.find(ast, check.pattern)
        report.checks_performed += 1 unless nodes_to_inspect.empty?
        report.nodes_inspected  += nodes_to_inspect.size

        issues = []
        nodes_to_inspect.each do |node|
          issues += check.visit(file, node)
        end
        report.issues += issues.reject { |i| ignored_lines.include?(i.line) }
      end
      report
    end

    def check_file(file)
      check(file, File.read(file))
    end

    private

    def check_classes
      # Get list of all subclasses of Scanny::Checks::Check.
      classes = []
      ObjectSpace.each_object(Class) do |klass|
        classes << klass if klass < Scanny::Checks::Check
      end

      # Filter out classes that are a superclass of some other class in the list.
      # This way only "leaf" classes remain.
      classes.reject! do |klass|
        classes.any? { |c| c < klass }
      end

      classes.map(&:new)
    end

    def extract_ignored_lines(input)
      ignored_lines = []
      input.split("\n").each_with_index do |line, i|
        if line =~ /SCANNY_IGNORE(_NEXT(?:_(\d+))?)?/
          if $2
            ignored_lines += ((i + 2)..(i + 1 + $2.to_i)).to_a
          else
            ignored_lines << i + ($1 ? 2 : 1)
          end
        end
      end
      ignored_lines
    end
  end
end
