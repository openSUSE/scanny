require "scanny"

RSpec::Matchers.define :parse do |input|
  chain :without_issues do
    @impact = nil
    @message = nil
  end

  chain :with_issue do |impact, message|
    @impact, @message = impact, message
  end

  match do |scanny|
    issues = scanny.check("scanned_file.rb", input)

    if @impact && @message
      issues.size.should == 1
      issues[0].impact.should == @impact
      issues[0].message.should == @message
    else
      issues.should be_empty
    end
  end
end
