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

    describe "==" do
      it "returns true when passed the same object" do
        @issue.should == @issue
      end

      it "returns true when passed an Issue initialized with the same parameters" do
        @issue.should == Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!")
      end

      it "returns false when passed some random object" do
        @issue.should_not == Object.new
      end

      it "returns false when passed a subclass of Issue initialized with the same parameters" do
        class SubclassedIssue < Issue
        end

        @issue.should_not == SubclassedIssue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!")
      end

      it "returns false when passed a ChoiceMatcher initialized with different parameters" do
        @issue.should_not == Issue.new("secure.rb", 42, :high, "Hey, I found unsecure code!")
        @issue.should_not == Issue.new("unsecure.rb", 43, :high, "Hey, I found unsecure code!")
        @issue.should_not == Issue.new("unsecure.rb", 42, :low, "Hey, I found unsecure code!")
        @issue.should_not == Issue.new("unsecure.rb", 42, :high, "Hey, I didn't find unsecure code!")
      end
    end

    describe "to_s" do
      it "returns correctly formatted string" do
        @issue.to_s.should == "[high] unsecure.rb:42: Hey, I found unsecure code!"
      end
    end
  end
end
