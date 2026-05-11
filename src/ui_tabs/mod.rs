pub mod add;
pub mod delete;
pub mod health;
pub mod modify;
pub mod view;

pub use add::render_add_tab;
pub use delete::render_delete_tab;
pub use health::render_health_tab;
pub use modify::render_modify_tab;
pub use view::render_view_tab;
