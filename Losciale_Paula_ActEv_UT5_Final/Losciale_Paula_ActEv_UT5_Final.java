import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

//Nota (Serializable)
class Nota implements Serializable {
    private String titulo;
    private String contenido;

    public Nota(String titulo, String contenido) {
        this.titulo = titulo;
        this.contenido = contenido;
    }

    public String getTitulo() { return titulo; }
    public String getContenido() { return contenido; }
    public void setTitulo(String titulo) { this.titulo = titulo; }
    public void setContenido(String contenido) { this.contenido = contenido; }
    @Override public String toString() { return titulo; }
}

//Gestor de usuarios y datos
class Usuarios {
    private static final String USERS_FILE = "users.txt";
    private static final String USERS_DIR = "usuarios";

    // Hashear contraseña con SHA-256
    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(password.getBytes());
        byte[] digest = md.digest();
        return bytesToHex(digest);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    //Guardar usuario
    public static void saveUser(String email, String passwordHash) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(USERS_FILE, true))) {
            writer.write(email + ":" + passwordHash);
            writer.newLine();
        }
    }

    //Cargar usuarios
    public static List<String[]> loadUsers() throws IOException {
        List<String[]> users = new ArrayList<>();
        if (Files.exists(Paths.get(USERS_FILE))) {
            try (BufferedReader reader = new BufferedReader(new FileReader(USERS_FILE))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(":");
                    if (parts.length == 2) {
                        users.add(parts);
                    }
                }
            }
        }
        return users;
    }

    //Guardar notas
    public static void saveNotes(String email, List<Nota> notas) throws IOException {
        String userDir = USERS_DIR + File.separator + email;
        Files.createDirectories(Paths.get(userDir));

        //Guardado atómico
        String tempPath = userDir + File.separator + "notas.tmp";
        String finalPath = userDir + File.separator + "notas.txt";

        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(tempPath))) {
            oos.writeObject(new ArrayList<>(notas));
        }

        Files.move(Paths.get(tempPath), Paths.get(finalPath),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    //Cargar notas
    public static List<Nota> loadNotes(String email) throws IOException, ClassNotFoundException {
        String userDir = USERS_DIR + File.separator + email;
        File file = new File(userDir + File.separator + "notas.txt");

        if (file.exists() && file.length() > 0) {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
                return (List<Nota>) ois.readObject();
            }
        }
        return new ArrayList<>();
    }
}

class MostrarLogin extends JFrame {
    private JTextField txtEmail;
    private JPasswordField txtPassword;

    public MostrarLogin() {
        setTitle("Inicio de Sesión");
        setSize(400, 250); // Aumentar el tamaño de la ventana
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5); // Margen entre los componentes

        //Esto es para el correo
        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("Correo:"), gbc);

        //Campo del correo
        gbc.gridx = 1;
        gbc.gridy = 0;
        txtEmail = new JTextField(20);
        panel.add(txtEmail, gbc);

        //Contraseña
        gbc.gridx = 0;
        gbc.gridy = 1;
        panel.add(new JLabel("Contraseña:"), gbc);

        //Campo de texto de contraseña
        gbc.gridx = 1;
        gbc.gridy = 1;
        txtPassword = new JPasswordField(20);
        panel.add(txtPassword, gbc);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        JButton btnLogin = new JButton("Iniciar Sesión");
        btnLogin.addActionListener(e -> login());
        JButton btnRegister = new JButton("Registrarse");
        btnRegister.addActionListener(e -> showRegister());
        buttonPanel.add(btnLogin);
        buttonPanel.add(btnRegister);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        panel.add(buttonPanel, gbc);

        add(panel);
    }

    private void login() {
        String email = txtEmail.getText().trim();
        String password = new String(txtPassword.getPassword());

        try {
            List<String[]> users = Usuarios.loadUsers();
            String hashedPassword = Usuarios.hashPassword(password);

            for (String[] user : users) {
                if (user[0].equals(email) && user[1].equals(hashedPassword)) {
                    List<Nota> notas = Usuarios.loadNotes(email);
                    openNotesWindow(email, notas);
                    dispose();
                    return;
                }
            }
            JOptionPane.showMessageDialog(this, "Credenciales incorrectas");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error: " + ex.getMessage());
        }
    }

    private void showRegister() {
        new MostrarRegistro().setVisible(true);
    }

    private void openNotesWindow(String email, List<Nota> notas) {
        SwingUtilities.invokeLater(() -> {
            MostrarNotas notesWindow = new MostrarNotas(email, notas);
            notesWindow.setVisible(true);
        });
    }
}

class MostrarRegistro extends JFrame {
    private JTextField txtEmail;
    private JPasswordField txtPassword;

    public MostrarRegistro() {
        setTitle("Registro");
        setSize(400, 250); // Aumentar el tamaño de la ventana
        setLocationRelativeTo(null);

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5); // Margen entre los componentes

        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("Correo:"), gbc);

        gbc.gridx = 1;
        gbc.gridy = 0;
        txtEmail = new JTextField(20);
        panel.add(txtEmail, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        panel.add(new JLabel("Contraseña:"), gbc);

        gbc.gridx = 1;
        gbc.gridy = 1;
        txtPassword = new JPasswordField(20);
        panel.add(txtPassword, gbc);

        //Botón de registro
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        JButton btnRegister = new JButton("Registrar");
        btnRegister.addActionListener(e -> register());
        buttonPanel.add(btnRegister);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        panel.add(buttonPanel, gbc);

        add(panel);
    }

    private void register() {
        String email = txtEmail.getText().trim();
        String password = new String(txtPassword.getPassword());

        if (email.isEmpty() || password.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Todos los campos son obligatorios");
            return;
        }

        if (!email.matches("^[\\w-.]+@([\\w-]+\\.)+[\\w-]{2,4}$")) {
            JOptionPane.showMessageDialog(this, "Correo inválido");
            return;
        }

        if (password.length() < 8) {
            JOptionPane.showMessageDialog(this, "La contraseña debe tener al menos 8 caracteres");
            return;
        }

        try {
            List<String[]> users = Usuarios.loadUsers();
            for (String[] user : users) {
                if (user[0].equals(email)) {
                    JOptionPane.showMessageDialog(this, "Este correo ya está registrado");
                    return;
                }
            }

            String hashedPassword = Usuarios.hashPassword(password);
            Usuarios.saveUser(email, hashedPassword);
            JOptionPane.showMessageDialog(this, "Registro exitoso");
            dispose();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error: " + ex.getMessage());
        }
    }
}

class MostrarNotas extends JFrame {
    private String userEmail;
    private List<Nota> notas;
    private DefaultListModel<Nota> modeloNotas = new DefaultListModel<>();
    private JList<Nota> listaNotas;
    private JTextField txtBusqueda, txtTitulo;
    private JTextArea txtContenido;

    public MostrarNotas(String email, List<Nota> notasUsuario) {
        this.userEmail = email;
        this.notas = new ArrayList<>(notasUsuario);
        actualizarModelo();

        setTitle("Notas de " + email);
        setSize(1100, 800);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(createButtonPanel(), BorderLayout.WEST);
        topPanel.add(createSearchPanel(), BorderLayout.EAST);

        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(createListPanel(), BorderLayout.WEST);
        mainPanel.add(createFormPanel(), BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton btnGuardar = new JButton("Guardar Cambios");
        btnGuardar.addActionListener(e -> guardarNotas());
        JButton btnLogout = new JButton("Cerrar Sesión");
        btnLogout.addActionListener(e -> logout());

        bottomPanel.add(btnGuardar);
        bottomPanel.add(btnLogout);
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        add(mainPanel);
    }

    private JPanel createListPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Notas guardadas"));

        listaNotas = new JList<>(modeloNotas);
        listaNotas.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        listaNotas.setFixedCellWidth(250);

        listaNotas.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) updateFields();
        });

        listaNotas.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) updateFields();
            }
        });

        panel.add(new JScrollPane(listaNotas), BorderLayout.CENTER);
        return panel;
    }

    private JPanel createFormPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("Edición de notas"));

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        txtTitulo = new JTextField();
        txtTitulo.setMaximumSize(new Dimension(400, 30));
        txtContenido = new JTextArea(15, 40);
        txtContenido.setFont(new Font("Arial", Font.PLAIN, 14));
        JScrollPane scroll = new JScrollPane(txtContenido);

        content.add(new JLabel("Título:"));
        content.add(txtTitulo);
        content.add(Box.createVerticalStrut(15));
        content.add(new JLabel("Contenido:"));
        content.add(scroll);

        panel.add(content, BorderLayout.NORTH);
        return panel;
    }

    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        String[] buttons = {"Guardar", "Editar", "Eliminar", "Limpiar"};
        for (String text : buttons) {
            panel.add(createButton(text));
        }
        return panel;
    }

    private JPanel createSearchPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

        txtBusqueda = new JTextField(25);
        txtBusqueda.setPreferredSize(new Dimension(200, 30));

        txtBusqueda.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { searchNotes(); }
            @Override public void removeUpdate(DocumentEvent e) { searchNotes(); }
            @Override public void changedUpdate(DocumentEvent e) { searchNotes(); }
        });

        panel.add(new JLabel("Buscar notas:"));
        panel.add(txtBusqueda);
        return panel;
    }

    private JButton createButton(String text) {
        JButton button = new JButton(text);
        button.setPreferredSize(new Dimension(100, 30));

        switch(text) {
            case "Guardar":
                button.addActionListener(e -> addNote());
                break;
            case "Editar":
                button.addActionListener(e -> editNote());
                break;
            case "Eliminar":
                button.addActionListener(e -> deleteNote());
                break;
            case "Limpiar":
                button.addActionListener(e -> clearFields());
                break;
        }
        return button;
    }

    private void addNote() {
        if (validateFields()) {
            Nota nuevaNota = new Nota(
                    txtTitulo.getText().trim(),
                    txtContenido.getText().trim()
            );

            if (existeTitulo(nuevaNota.getTitulo())) {
                JOptionPane.showMessageDialog(this, "Ya existe una nota con este título");
                return;
            }

            notas.add(nuevaNota);
            actualizarModelo();
            clearFields();
        }
    }

    private void editNote() {
        int selectedIndex = listaNotas.getSelectedIndex();
        if (selectedIndex == -1) {
            JOptionPane.showMessageDialog(this, "Seleccione una nota para editar");
            return;
        }

        Nota nota = notas.get(selectedIndex);
        nota.setTitulo(txtTitulo.getText().trim());
        nota.setContenido(txtContenido.getText().trim());
        actualizarModelo();
        clearFields();
    }

    private void deleteNote() {
        int selectedIndex = listaNotas.getSelectedIndex();
        if (selectedIndex == -1) {
            JOptionPane.showMessageDialog(this, "Seleccione una nota para eliminar");
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(
                this,
                "¿Eliminar esta nota?",
                "Confirmar eliminación",
                JOptionPane.YES_NO_OPTION
        );

        if (confirm == JOptionPane.YES_OPTION) {
            notas.remove(selectedIndex);
            actualizarModelo();
            clearFields();
        }
    }

    private void searchNotes() {
        String query = txtBusqueda.getText().toLowerCase();
        modeloNotas.clear();

        for (Nota nota : notas) {
            if (nota.getTitulo().toLowerCase().contains(query) ||
                    nota.getContenido().toLowerCase().contains(query)) {
                modeloNotas.addElement(nota);
            }
        }
    }

    private void updateFields() {
        Nota selected = listaNotas.getSelectedValue();
        if (selected != null) {
            txtTitulo.setText(selected.getTitulo());
            txtContenido.setText(selected.getContenido());
        }
    }

    private boolean validateFields() {
        if (txtTitulo.getText().trim().isEmpty() || txtContenido.getText().trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, "Todos los campos son obligatorios");
            return false;
        }
        return true;
    }

    private boolean existeTitulo(String titulo) {
        return notas.stream().anyMatch(n -> n.getTitulo().equalsIgnoreCase(titulo));
    }

    private void clearFields() {
        txtTitulo.setText("");
        txtContenido.setText("");
        listaNotas.clearSelection();
    }

    private void actualizarModelo() {
        modeloNotas.clear();
        notas.forEach(modeloNotas::addElement);
    }

    private void guardarNotas() {
        try {
            Usuarios.saveNotes(userEmail, notas);
            JOptionPane.showMessageDialog(this, "Tus notas se guardaron");
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Error al guardar: " + ex.getMessage());
        }
    }

    private void logout() {
        guardarNotas();
        new MostrarLogin().setVisible(true);
        dispose();
    }
}

public class Losciale_Paula_ActEv_UT5_Final {
    public static void main(String[] args) {
        System.out.println("Prueba a crear un usuario y luego inicias sesión con el mismo.");
        System.out.println("Esta es la url del repositorio del proyecto subido a github: https://github.com/PaulaLosciale/Losciale_Paula_ActEv_UT5_Final");
        SwingUtilities.invokeLater(() -> {
            new MostrarLogin().setVisible(true);
        });
    }
}