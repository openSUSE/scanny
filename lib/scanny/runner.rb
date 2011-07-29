require "yaml"
require "machete"

module Scanny
  class Runner
    attr_reader :issues

    def initialize(*checks)
      if checks.empty?
        names = Scanny::Checks.constants.grep(/.+Check$/).map
        @checks = names.map { |name| Scanny::Checks.const_get(name).new }
      else
        @checks = checks
      end
    end

    def check(filename, content)
      @checks ||= load_checks
      @issues = []

      ast = parse(filename, content)
      @checks.each do |check|
        Machete.find(ast, check.pattern).each do |node|
          @issues += check.visit(filename, node)
        end
      end
    end

    def check_content(content, filename = "dummy-file.rb")
      check(filename, content)
    end

    def check_file(filename)
      check(filename, File.read(filename))
    end

    private

    def parse(filename, content)
      begin
        content.to_ast
      rescue Exception => e
        puts "#{filename} looks like it's not a valid Ruby file.  Skipping..." if ENV["ROODI_DEBUG"]
        nil
      end
    end
  end
end
