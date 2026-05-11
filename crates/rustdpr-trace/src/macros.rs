#[macro_export]
macro_rules! dpr_hit {
    ($id:expr) => {{
        $crate::hit($id);
    }};
}