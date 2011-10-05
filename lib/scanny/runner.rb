require "yaml"
require "machete"

module Scanny
  class Runner
    attr_reader :checks

    def initialize(*checks)
      if checks.empty?
        names = Scanny::Checks.constants.grep(/.+Check$/).map
        @checks = names.map { |name| Scanny::Checks.const_get(name).new }
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
