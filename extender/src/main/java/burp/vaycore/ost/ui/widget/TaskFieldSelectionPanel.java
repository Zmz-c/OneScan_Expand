package burp.vaycore.ost.ui.widget;

import burp.vaycore.ost.manager.TaskPersistenceManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class TaskFieldSelectionPanel extends JPanel {

    private final List<JCheckBox> boxes = new ArrayList<>();

    public TaskFieldSelectionPanel(List<String> selectedKeys) {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(new EmptyBorder(5, 5, 5, 5));
        Set<String> selected = new HashSet<>(TaskPersistenceManager.normalizeFieldKeys(selectedKeys));
        for (TaskPersistenceManager.FieldDef field : TaskPersistenceManager.getSelectableFields()) {
            JCheckBox box = new JCheckBox(field.label());
            box.setActionCommand(field.key());
            box.setSelected(selected.contains(field.key()));
            box.setAlignmentX(LEFT_ALIGNMENT);
            boxes.add(box);
            add(box);
        }
    }

    public List<String> getSelectedFieldKeys() {
        ArrayList<String> result = new ArrayList<>();
        for (JCheckBox box : boxes) {
            if (box.isSelected()) {
                result.add(box.getActionCommand());
            }
        }
        return TaskPersistenceManager.normalizeFieldKeys(result);
    }
}
