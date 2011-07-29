require "scanny"

RSpec.configure do |c|
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
    @impact  = nil
    @message = nil
    @cwe     = nil
  end

  chain :with_issue do |impact, message, cwe|
    @impact, @message, @cwe = impact, message, cwe
  end

  match do |scanny|
    issues = scanny.check("scanned_file.rb", input)

    if @impact && @message
      issues.size.should == 1
      issues[0].impact.should == @impact
      issues[0].message.should == @message
      issues[0].cwe.should == @cwe
    else
      issues.should be_empty
    end
  end
end
