require "spec_helper"

module Scanny::Checks
  describe Check do
    it "reports issues" do
      check = TestCheck.new
      issues = check.visit("unsecure.rb", Rubinius::AST::FixnumLiteral.new(1, 42))

      issues.should == [
        Scanny::Issue.new("unsecure.rb", 1, :high, "Hey, I found unsecure code!", 42),
        Scanny::Issue.new("unsecure.rb", 1, :high, "Hey, I found more unsecure code!", 43),
        Scanny::Issue.new("unsecure.rb", 1, :low,  "OK, this is unsecure too, but not that much")
      ]
    end
  end
end
