require 'pp'
require 'yaml'
require 'machete'

module Scanny
  class Runner
    DEFAULT_CONFIG = File.join(File.dirname(__FILE__), "..", "..", "scanny.yml")

    attr_reader :issues
    attr_writer :config

    def initialize(*checks)
      @config = DEFAULT_CONFIG
      @checks = checks unless checks.empty?
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

    def print(filename, content)
      node = content.to_ast
      puts "Line: #{node.line}"
      pp node
    end

    def print_content(content)
      print("dummy-file.rb", content)
    end

    def print_file(filename)
      print(filename, File.read(filename))
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

    def load_checks
      check_objects = []
      checks = YAML.load_file @config
      checks.each do |check|
        klass = eval("Scanny::Checks::#{check[0]}")
        check_objects << (check[1].empty? ? klass.new : klass.new(check[1]))
      end
      check_objects
    end
  end
end
