#[macro_use]
extern crate napi_rs as napi;
#[macro_use]
extern crate napi_rs_derive;

use argon2::{hash_raw, Config};
use flatbuffers::get_root;
use napi::{ArrayBuffer, Buffer, CallContext, Env, Error, Object, Result, Status, Value};
use option_generated::argon_2;

#[allow(dead_code, unused_imports)]
#[path = "./option_generated.rs"]
mod option_generated;

#[cfg(unix)]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

register_module!(argon2, init);

fn init(env: &Env, exports: &mut Value<Object>) -> Result<()> {
  exports.set_property(
    env.create_string("hash")?,
    env.create_function("hash", hash)?,
  )?;
  Ok(())
}

#[js_function(3)]
fn hash(ctx: CallContext) -> Result<Value<Buffer>> {
  let input = ctx.get::<Buffer>(0)?;
  let salt = ctx.get::<Buffer>(1)?;
  let options_buffer = ctx.get::<ArrayBuffer>(2)?;
  let options = argon_2::Options::init_from_table(get_root::<flatbuffers::Table>(&options_buffer));
  let result = hash_raw(&input, &salt, &Config::default()).map_err(|e| Error {
    status: Status::GenericFailure,
    reason: Some(format!("hash password failed: {:?}", e)),
  })?;
  ctx.env.create_buffer_with_data(result)
}
