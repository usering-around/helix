use crate::compositor::Compositor;
use crate::ui;
use helix_view::events::DocumentDidOpen;
use helix_view::handlers::Handlers;
use helix_view::theme::Modifier;
use helix_view::theme::Style;
use helix_view::Editor;
use tui::text::Span;
use tui::text::Spans;
use ui::overlay::overlaid;

pub fn trust_dialog(editor: &mut Editor, compositor: &mut Compositor) {
    let first_option = "Do not trust";
    let second_option = "Trust";
    let third_option = "Trust completely";
    let options = vec![
                        (
                            Span::styled(
                                first_option,
                                Style::new().fg(helix_view::theme::Color::Red)
                                .add_modifier(Modifier::BOLD),
                            ),
                            "Do not allow the usage of LSPs, formatters, debuggers and the such. Local config can manually be trusted."
                                .to_string(),
                        ),
                        (
                            Span::styled(
                                second_option,
                                Style::new().fg(helix_view::theme::Color::Yellow)
                                                            .add_modifier(Modifier::BOLD),
                            ),
                            "Allow the usage of LSPs, formatters, debuggers and the such. However, local config will need to be manually trusted.".to_string(),
                        ),
                        (
                            Span::styled(
                                third_option,
                                Style::new().fg(helix_view::theme::Color::Green)
                                .add_modifier(Modifier::BOLD),
                            ),
                            "Allow the usage of LSPs, formatters, debuggers and such, along with loading the local config of this workspace.".to_string(),
                        ),
                    ];

    let Some(file_path) = doc!(editor).path() else {
        // helix doesn't send the document open event when it has no paths, but the user may still use :trust-dialog anyways.
        editor.set_error("Could not open trust dialog: the file does not have a path.");
        return;
    };
    let path = helix_loader::find_workspace_in(file_path).0;

    let columns = [
        ui::PickerColumn::new(
            format!("Trust workspace '{}'?", path.display()),
            |(t, _): &(Span<'_>, String), _| Spans(vec![t.clone()]).into(),
        ),
        ui::PickerColumn::new("", |(_, explain): &(_, String), _| explain.as_str().into()),
    ];

    let picker = ui::Picker::new(columns, 0, options, (), move |cx, str, _action| {
        let maybe_err = if str.0.content == first_option {
            cx.editor.untrust_workspace()
        } else if str.0.content == second_option {
            cx.editor.trust_workspace(false)
        } else {
            cx.editor.trust_workspace(true)
        };
        if let Err(e) = maybe_err {
            cx.editor.set_status(e.to_string());
        }
    });
    compositor.push(Box::new(overlaid(picker)));
}

pub(super) fn register_hooks(_handlers: &Handlers) {
    helix_event::register_hook!(move |event: &mut DocumentDidOpen<'_>| {
        if event
            .editor
            .document(event.doc)
            .is_some_and(|doc| doc.is_trusted.is_none())
        {
            tokio::spawn(async move {
                crate::job::dispatch(move |editor, compositor| {
                    trust_dialog(editor, compositor);
                })
                .await;
            });
        }

        Ok(())
    });
}
