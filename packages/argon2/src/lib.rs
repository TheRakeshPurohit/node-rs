#[macro_use]
extern crate napi_rs as napi;
#[macro_use]
extern crate napi_rs_derive;

use napi::{Buffer, CallContext, Env, Object, Result, Value};

#[cfg(unix)]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

register_module!(argon2, init);

fn init(env: &Env, exports: &mut Value<Object>) -> Result<()> {
  Ok(())
}

#[js_function(2)]
fn hash(ctx: CallContext) -> Result<Value<Buffer>> {
  let input = ctx.get::<Buffer>(0)?;
  let options = ctx.get::<Object>(1)?;

  ctx.env.create_buffer_with_data(vec![])
}
