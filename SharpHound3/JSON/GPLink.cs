namespace SharpHound3.JSON
{
    internal class GPLink
    {
        private string _guid;

        public bool? IsEnforced { get; set; }
        public string Guid
        {
            get => _guid;
            set => _guid = value.ToUpper();
        }
    }
}
