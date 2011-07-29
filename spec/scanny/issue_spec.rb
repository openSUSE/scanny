require "spec_helper"

module Scanny
  describe Issue do
    describe "initialize" do
      describe "when not passed \"cwe\"" do
        it "sets attributes correctly" do
          issue = Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!")

          issue.file.should == "unsecure.rb"
          issue.line.should == 42
          issue.impact.should == :high
          issue.message.should == "Hey, I found unsecure code!"
        end
      end

      describe "when passed \"cwe\"" do
        it "sets \"cwe\" correctly" do
          issue = Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!", 43)

          issue.cwe.should == 43
        end
      end
    end

    describe "==" do
      before :each do
        @issue = Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!", 43)
      end

      it "returns true when passed the same object" do
        @issue.should == @issue
      end

      it "returns true when passed an Issue initialized with the same parameters" do
        @issue.should == Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!", 43)
      end

      it "returns false when passed some random object" do
        @issue.should_not == Object.new
      end

      it "returns false when passed a subclass of Issue initialized with the same parameters" do
        class SubclassedIssue < Issue
        end

        @issue.should_not == SubclassedIssue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!", 43)
      end

      it "returns false when passed a ChoiceMatcher initialized with different parameters" do
        @issue.should_not == Issue.new("secure.rb", 42, :high, "Hey, I found unsecure code!", 43)
        @issue.should_not == Issue.new("unsecure.rb", 43, :high, "Hey, I found unsecure code!", 43)
        @issue.should_not == Issue.new("unsecure.rb", 42, :low, "Hey, I found unsecure code!", 43)
        @issue.should_not == Issue.new("unsecure.rb", 42, :high, "Hey, I didn't find unsecure code!", 43)
        @issue.should_not == Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!", 44)
      end
    end

    describe "to_s" do
      describe "called on issue without CWE" do
        it "returns correctly formatted string" do
          issue = Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!")
          issue.to_s.should == "[high] unsecure.rb:42: Hey, I found unsecure code!"
        end
      end

      describe "called on issue with one CWE" do
        it "returns correctly formatted string" do
          issue = Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!", 43)
          issue.to_s.should == "[high] unsecure.rb:42: Hey, I found unsecure code! (CWE-43)"
        end
      end

      describe "called on issue with multiple CWEs" do
        it "returns correctly formatted string" do
          issue = Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!", [43, 44, 45])
          issue.to_s.should == "[high] unsecure.rb:42: Hey, I found unsecure code! (CWE-43, CWE-44, CWE-45)"
        end
      end
    end
  end
end
