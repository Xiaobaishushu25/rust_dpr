#[macro_export]
macro_rules! dpr_hit {
    ($id:expr) => {{
        $crate::hit($id);
    }};
}

#[macro_export]
macro_rules! dpr_enter {
    ($function:expr) => {{
        $crate::enter_function($function);
    }};
}

#[macro_export]
macro_rules! dpr_exit {
    ($function:expr) => {{
        $crate::exit_function($function);
    }};
}

#[macro_export]
macro_rules! dpr_function {
    ($function:expr) => {{
        $crate::enter_function($function);
        $crate::FunctionTraceGuard::new($function)
    }};
}
