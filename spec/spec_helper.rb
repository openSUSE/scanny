require "scanny"
require 'xpath_matcher'

module CheckSpecHelpers
  def issue(*args)
    Scanny::Issue.new("scanned_file.rb", 1, *args)
  end
end

RSpec.configure do |c|
  c.include CheckSpecHelpers
  c.color_enabled = true
end

module Scanny
  module Checks
    class TestCheck < Check
      def pattern
        'FixnumLiteral'
      end

      def check(node)
        issue :high, "Hey, I found unsecure code!", :cwe => 42
        issue :high, "Hey, I found more unsecure code!", :cwe => 43
        issue :low,  "OK, this is unsecure too, but not that much"
      end
    end
  end
end

RSpec::Matchers.define :check do |input|
  chain :without_issues do
    @type = :no_issues
  end

  chain :with_n_issues do |count|
    @type = :issue_count
    @count = count
  end

  chain :with_issue do |issue|
    @type = :issue
    @issue = issue
  end

  match do |scanny|
    report = scanny.check("scanned_file.rb", input)

    case @type
      when :no_issues
        report.issues.should be_empty

      when :issue_count
        report.issues.size.should == @count

      when :issue
        report.issues.size.should == 1
        report.issues[0].should == @issue

      else
        raise "Unknown check type: #{type.inspect}."
    end
  end
end
