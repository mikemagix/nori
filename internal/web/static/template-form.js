const form = document.querySelector('[data-deployment-form]');
const mode = form?.querySelector('[data-deployment-mode]');

function syncMode() {
  if (!form || !mode) return;
  for (const panel of form.querySelectorAll('[data-deployment-mode-panel]')) {
    panel.hidden = panel.dataset.deploymentModePanel !== mode.value;
	for (const control of panel.querySelectorAll('input, select, textarea, button')) {
		control.disabled = panel.hidden;
	}
  }
}

mode?.addEventListener('change', syncMode);
syncMode();
