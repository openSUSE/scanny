require "scanny"

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
    @issue = nil
  end

  chain :with_issue do |issue|
    @issue = issue
  end

  match do |scanny|
    report = scanny.check("scanned_file.rb", input)

    if @issue
      report.issues.size.should == 1
      report.issues[0].should == @issue
    else
      report.issues.should be_empty
    end
  end
end
