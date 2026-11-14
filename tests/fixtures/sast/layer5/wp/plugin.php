<?php
/* Plugin Name: L5 */
add_action('admin_post_l5_save', 'l5_save');
function l5_save() { update_option('l5_banner', $_POST['banner']); }
add_action('admin_post_l5_save_safe', 'l5_save_safe');
function l5_save_safe() { check_admin_referer('l5'); update_option('l5_footer', sanitize_text_field($_POST['footer'])); }
function l5_render() { echo get_option('l5_banner'); }
function l5_render_safe() { echo esc_html(get_option('l5_banner')); }
function l5_render_other() { echo get_option('blogname'); }
