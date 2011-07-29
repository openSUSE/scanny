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
      ast = input.to_ast

      issues = []
      @checks.each do |check|
        Machete.find(ast, check.pattern).each do |node|
          issues += check.visit(file, node)
        end
      end
      issues
    end

    def check_file(file)
      check(file, File.read(file))
    end
  end
end
