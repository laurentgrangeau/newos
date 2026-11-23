#![forbid(unsafe_code)]
#![allow(
    clippy::type_complexity,
    clippy::collapsible_if,
    clippy::needless_range_loop,
    clippy::manual_is_multiple_of
)]

mod helpers;
mod tier1_features;
mod tier2_boundaries;
mod tier3_combinations;
mod tier4_scenarios;
mod tier5_adversarial;
