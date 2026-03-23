// app.js — Global Bootstrap tooltip init + minor UI helpers

document.addEventListener('DOMContentLoaded', () => {
  // Initialize all Bootstrap tooltips
  document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
    new bootstrap.Tooltip(el, { placement: 'top', trigger: 'hover' });
  });

  // Auto-dismiss alerts after 4s
  document.querySelectorAll('.alert.alert-success, .alert.alert-warning').forEach(el => {
    setTimeout(() => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(el);
      if (bsAlert) bsAlert.close();
    }, 4000);
  });
});
