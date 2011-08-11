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
      report = Report.new(file)
      ast    = input.to_ast

      @checks.each do |check|
        nodes_to_inspect = Machete.find(ast, check.pattern)
        report.checks_performed += 1 unless nodes_to_inspect.empty?
        report.nodes_inspected  += nodes_to_inspect.size

        nodes_to_inspect.each do |node|
          report.issues += check.visit(file, node)
        end
      end
      report
    end

    def check_file(file)
      check(file, File.read(file))
    end
  end
end
