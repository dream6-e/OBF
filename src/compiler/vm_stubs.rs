pub struct GcRef<T>(std::marker::PhantomData<T>);
pub trait Trace {}
pub struct Closure;
pub struct LuaThread;
pub struct LuaString;
pub struct Table;
