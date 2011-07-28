require "spec_helper"

module Scanny
  describe Issue do
    before :each do
      @issue = Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!")
    end

    describe "initialize" do
      it "sets attributes correctly" do
        @issue.file.should == "unsecure.rb"
        @issue.line.should == 42
        @issue.impact.should == :high
        @issue.message.should == "Hey, I found unsecure code!"
      end
    end

    describe "to_s" do
      it "returns correctly formatted string" do
        @issue.to_s.should == "[high] unsecure.rb:42: Hey, I found unsecure code!"
      end
    end
  end
end
