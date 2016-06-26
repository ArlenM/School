namespace Malware_Scanner
{
    partial class scannerForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.scanButton = new System.Windows.Forms.Button();
            this.consoleOutput = new System.Windows.Forms.RichTextBox();
            this.specificScanButton = new System.Windows.Forms.Button();
            this.openFileDialog = new System.Windows.Forms.OpenFileDialog();
            this.button1 = new System.Windows.Forms.Button();
            this.button2 = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // scanButton
            // 
            this.scanButton.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.scanButton.Location = new System.Drawing.Point(9, 261);
            this.scanButton.Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            this.scanButton.Name = "scanButton";
            this.scanButton.Size = new System.Drawing.Size(532, 42);
            this.scanButton.TabIndex = 0;
            this.scanButton.Text = "Scan";
            this.scanButton.UseVisualStyleBackColor = true;
            this.scanButton.Click += new System.EventHandler(this.scanButton_Click);
            // 
            // consoleOutput
            // 
            this.consoleOutput.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.consoleOutput.Location = new System.Drawing.Point(9, 10);
            this.consoleOutput.Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            this.consoleOutput.Name = "consoleOutput";
            this.consoleOutput.Size = new System.Drawing.Size(534, 247);
            this.consoleOutput.TabIndex = 2;
            this.consoleOutput.Text = "";
            // 
            // specificScanButton
            // 
            this.specificScanButton.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.specificScanButton.Location = new System.Drawing.Point(9, 308);
            this.specificScanButton.Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            this.specificScanButton.Name = "specificScanButton";
            this.specificScanButton.Size = new System.Drawing.Size(532, 23);
            this.specificScanButton.TabIndex = 3;
            this.specificScanButton.Text = "Scan Specific File";
            this.specificScanButton.UseVisualStyleBackColor = true;
            this.specificScanButton.Click += new System.EventHandler(this.specificScanButton_Click);
            // 
            // openFileDialog
            // 
            this.openFileDialog.FileName = "Select Scan File";
            // 
            // button1
            // 
            this.button1.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.button1.Location = new System.Drawing.Point(11, 213);
            this.button1.Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(532, 42);
            this.button1.TabIndex = 4;
            this.button1.Text = "Scan C";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // button2
            // 
            this.button2.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.button2.Location = new System.Drawing.Point(11, 165);
            this.button2.Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(532, 42);
            this.button2.TabIndex = 5;
            this.button2.Text = "Scan URLs";
            this.button2.UseVisualStyleBackColor = true;
            this.button2.Click += new System.EventHandler(this.button2_Click);
            // 
            // scannerForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(550, 341);
            this.Controls.Add(this.button2);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.specificScanButton);
            this.Controls.Add(this.consoleOutput);
            this.Controls.Add(this.scanButton);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            this.MaximizeBox = false;
            this.Name = "scannerForm";
            this.ShowIcon = false;
            this.Text = "Malware Scanner";
            this.Load += new System.EventHandler(this.scannerForm_Load);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button scanButton;
        private System.Windows.Forms.RichTextBox consoleOutput;
        private System.Windows.Forms.Button specificScanButton;
        private System.Windows.Forms.OpenFileDialog openFileDialog;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.Button button2;
    }
}

