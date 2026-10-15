document.addEventListener('DOMContentLoaded', () => {
  const store = document.getElementById('store-select');
  const city = document.getElementById('city-field');
  const supervisor = document.getElementById('supervisor-field');
  function updateStoreMeta() {
    const option = store && store.options[store.selectedIndex];
    if (option && option.value) { city.value = option.dataset.city || ''; supervisor.value = option.dataset.supervisor || ''; }
    else { if (city) city.value = ''; if (supervisor) supervisor.value = ''; }
  }
  if (store) { store.addEventListener('change', updateStoreMeta); updateStoreMeta(); }
  document.querySelectorAll('form[data-confirm]').forEach(form => form.addEventListener('submit', e => { if (!confirm(form.dataset.confirm)) e.preventDefault(); }));
});
