module ConstSpecHelpers
  def with_const(const, &block)
    saved_consts = {}
    const.each do |const, val|
      saved_consts[const] = Object.const_get(const)
      Object.const_set(const, val)
    end

    begin
      block.call
    ensure
      const.each_key do |const|
        Object.const_set(const, saved_consts[ const ])
      end
    end
  end

  def with_ruby(engine = "rbx", version = '1.9.3', &block)
    with_const(:RUBY_VERSION => version,:RUBY_ENGINE => engine, &block)
  end

  def silence
    orig_stdout = $stderr
    $stderr = File.new('/dev/null', 'w')
    yield
  ensure
    $stderr = orig_stdout
  end

  def load_with(engine, version, file)
    silence do
      with_ruby(engine, version) { load(file) }
    end
  end
end

