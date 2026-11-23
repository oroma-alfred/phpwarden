<?php
/* Plugin Name: Shady Plug  Version: 2.0 */
function shadyplug_widget() { echo '<div class="shady">Hello</div>'; }
add_action('wp_footer', 'shadyplug_widget');
