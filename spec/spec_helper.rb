require "scanny"

RSpec::Matchers.define :parse do |content|
  chain :without_issues do
    @impact = nil
    @message = nil
  end

  chain :with_issue do |impact, message|
    @impact, @message = impact, message
  end

  match do |scanny|
    scanny.check_content(content)
    issues = scanny.issues

    if @impact && @message
      issues.size.should == 1
      issues[0].impact.should == @impact
      issues[0].message.should == @message
    else
      issues.should be_empty
    end
  end
end
